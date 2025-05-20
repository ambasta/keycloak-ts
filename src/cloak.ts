import { randomUUID } from "crypto";

import type {
  IAccessTokenResponse,
  IJsonConfig,
  IKeycloakAccountOptions,
  IKeycloakAdapter,
  IKeycloakConfig,
  IKeycloakInitOptions,
  IKeycloakLoginOptions,
  IKeycloakLogoutOptions,
  IKeycloakProfile,
  IKeycloakRegisterOptions,
  IOpenIdProviderMetadata,
  KeycloakFlow,
  KeycloakResponseMode,
} from "./types.ts";
import {
  decodeToken,
  isObject,
  sha256Digest,
  type IEndpoints,
} from "./helpers.ts";
import { NetworkError } from "./error.ts";
import { createCallbackStorage } from "./storage.ts";
import { generateCodeVerifier, generatePkceChallenge } from "./pkce.ts";

const CONTENT_TYPE_JSON = "application/json";

const arrayHas = <T>(arr: readonly T[], val: T): boolean => arr.includes(val);

const buildAuthorizationHeader = (token: string): [string, string] => {
  if (!token) throw new Error("Token required for Authorization header");
  return ["Authorization", `Bearer ${token}`];
};

const createLogger =
  (fn: (...args: unknown[]) => void) =>
  (...args: unknown[]): void => {
    if ((globalThis as any).enableLogging) fn(...args);
  };

const fetchWithErrorHandling = async (
  url: string,
  init?: RequestInit,
): Promise<Response> => {
  const response = await fetch(url, init);
  if (!response.ok)
    throw new NetworkError("Server responded with an invalid status.", {
      response,
    });
  return response;
};

const fetchJSON = async <T = unknown>(
  url: string,
  init: RequestInit = {},
): Promise<T> => {
  const headers = new Headers(init.headers);
  headers.set("Accept", CONTENT_TYPE_JSON);
  const response = await fetchWithErrorHandling(url, { ...init, headers });
  return (await response.json()) as T;
};

interface ICallbackState {
  state: string;
  nonce: string;
  redirectUri: string;
  loginOptions?: IKeycloakLoginOptions;
  prompt?: string;
  pkceCodeVerifier?: string;
  expires?: number;
}

const defaultAdapter = (kc: Keycloak): IKeycloakAdapter => ({
  login: async (options?: IKeycloakLoginOptions) => {
    window.location.assign(await kc.createLoginUrl(options));
  },
  logout: async (options?: IKeycloakLogoutOptions) => {
    const logoutMethod = options?.logoutMethod ?? kc.logoutMethod;
    if (logoutMethod === "GET") {
      window.location.replace(kc.createLogoutUrl(options));
      return;
    }
    const form = document.createElement("form");
    form.setAttribute("method", "POST");
    form.setAttribute("action", kc.createLogoutUrl(options));
    form.style.display = "none";
    const data: Record<string, string | undefined> = {
      id_token_hint: kc.idToken,
      client_id: kc.clientId,
      post_logout_redirect_uri: kc.adapter.redirectUri(options),
    };
    Object.entries(data).forEach(([name, value]) => {
      if (!value) return;
      const input = document.createElement("input");
      input.setAttribute("type", "hidden");
      input.setAttribute("name", name);
      input.setAttribute("value", value);
      form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
  },
  register: async (options?: IKeycloakRegisterOptions) => {
    window.location.assign(await kc.createRegisterUrl(options));
  },
  accountManagement: () => {
    const accountUrl = kc.createAccountUrl();
    if (accountUrl) {
      window.location.href = accountUrl;
    } else {
      throw new Error("Not supported by the OIDC server");
    }
  },
  redirectUri: (options?: { redirectUri?: string }) =>
    options?.redirectUri || kc.redirectUri || location.href,
});

// --- KEYCLOAK MAIN CLASS ---
interface IPromiseBox {
  setSuccess: (value?: unknown) => void;
  setError: (value?: unknown) => void;
}

interface ILoginIFrameOptions {
  enable: boolean;
  callbackList: Array<IPromiseBox>;
  interval: number;
  iframe?: HTMLIFrameElement;
  iframeOrigin?: string;
}

export class Keycloak {
  // Required config values
  clientId!: string;
  realm!: string;
  authServerUrl?: string;

  // Stateful properties
  public authenticated = false;
  public didInitialize = false;
  public profile?: IKeycloakProfile;
  public userInfo?: Record<string, unknown>;
  public token?: string;
  public refreshToken?: string;
  public idToken?: string;
  public tokenParsed?: Record<string, unknown>;
  public refreshTokenParsed?: Record<string, unknown>;
  public idTokenParsed?: Record<string, unknown>;
  public sessionId?: string;
  public subject?: string;
  public realmAccess?: { roles: string[] };
  public resourceAccess?: Record<string, { roles: string[] }>;
  public timeSkew?: number;
  public flow: KeycloakFlow = "standard";
  public responseMode: KeycloakResponseMode = "fragment";
  public responseType = "code";
  public pkceMethod: "S256" | false = "S256";
  public scope?: string;
  public enableLogging = false;
  public silentCheckSsoRedirectUri?: string;
  public silentCheckSsoFallback = true;
  public redirectUri?: string;
  public logoutMethod: "GET" | "POST" = "GET";
  public messageReceiveTimeout = 10000;

  // Endpoints and adapter
  public endpoints!: IEndpoints;
  public adapter!: IKeycloakAdapter;

  // Events
  public onReady?: (authenticated: boolean) => void;
  public onAuthSuccess?: () => void;
  public onAuthError?: (err?: unknown) => void;
  public onActionUpdate?: (status: string, action: string) => void;
  public onAuthRefreshSuccess?: () => void;
  public onAuthRefreshError?: () => void;
  public onAuthLogout?: () => void;
  public onTokenExpired?: () => void;

  // Private members
  #config: IKeycloakConfig | string;
  #loginIframe: ILoginIFrameOptions = {
    enable: true,
    callbackList: [],
    interval: 5,
  };
  #useNonce = true;
  #callbackStorage = createCallbackStorage();
  #tokenTimeoutHandle?: number;
  #refreshQueue: Array<{
    setSuccess: (v?: unknown) => void;
    setError: (v?: unknown) => void;
  }> = [];

  constructor(config: IKeycloakConfig | string) {
    this.#config = config;

    if (!(this instanceof Keycloak)) throw new Error("Must use new Keycloak()");

    if (typeof this.#config !== "string" && !isObject(config))
      throw new Error("Config must be object or url string");

    if (isObject<IKeycloakConfig>(this.#config)) {
      const required: (keyof IKeycloakConfig)[] =
        "oidcProvider" in this.#config
          ? ["clientId"]
          : ["url", "realm", "clientId"];

      required.forEach((property) => {
        if (!this.#config[property])
          throw new Error(`Missing required config property '${property}'`);
      });
    }
    if (!globalThis.isSecureContext) {
      createLogger(console.warn)(
        "[KEYCLOAK] Keycloak JS must be used in a 'secure context'. See: https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts",
      );
    }
  }

  public init = async (
    initOptions: IKeycloakInitOptions = {},
  ): Promise<boolean> => {
    if (this.didInitialize)
      throw new Error("Keycloak instance already initialized");
    this.didInitialize = true;
    this.authenticated = false;

    // Adapter loading (only "default" is implemented here, for cross-platform Node/Browser)
    this.adapter = defaultAdapter(this);

    // Option handling
    if (typeof initOptions.useNonce !== "undefined")
      this.#useNonce = initOptions.useNonce;
    if (typeof initOptions.checkLoginIframe !== "undefined")
      this.#loginIframe.enable = initOptions.checkLoginIframe;
    if (initOptions.checkLoginIframeInterval)
      this.#loginIframe.interval = initOptions.checkLoginIframeInterval;
    if (initOptions.onLoad === "login-required")
      (this as any).loginRequired = true;
    if (initOptions.responseMode) this.responseMode = initOptions.responseMode;
    if (initOptions.flow) {
      switch (initOptions.flow) {
        case "standard":
          this.responseType = "code";
          break;
        case "implicit":
          this.responseType = "id_token token";
          break;
        case "hybrid":
          this.responseType = "code id_token token";
          break;
        default:
          throw new Error("Invalid flow");
      }
      this.flow = initOptions.flow;
    }
    if (initOptions.timeSkew !== undefined)
      this.timeSkew = initOptions.timeSkew;
    if (initOptions.redirectUri) this.redirectUri = initOptions.redirectUri;
    if (initOptions.silentCheckSsoRedirectUri)
      this.silentCheckSsoRedirectUri = initOptions.silentCheckSsoRedirectUri;
    this.silentCheckSsoFallback =
      typeof initOptions.silentCheckSsoFallback === "boolean"
        ? initOptions.silentCheckSsoFallback
        : true;
    this.pkceMethod =
      typeof initOptions.pkceMethod !== "undefined"
        ? initOptions.pkceMethod
        : "S256";
    this.enableLogging =
      typeof initOptions.enableLogging === "boolean"
        ? initOptions.enableLogging
        : false;
    this.logoutMethod = initOptions.logoutMethod === "POST" ? "POST" : "GET";
    if (typeof initOptions.scope === "string") this.scope = initOptions.scope;
    this.messageReceiveTimeout =
      typeof initOptions.messageReceiveTimeout === "number" &&
      initOptions.messageReceiveTimeout > 0
        ? initOptions.messageReceiveTimeout
        : 10000;
    if (!this.responseMode) this.responseMode = "fragment";
    if (!this.responseType) {
      this.responseType = "code";
      this.flow = "standard";
    }

    await this.#loadConfig();

    // (handle SSO login, token parsing, silent check, etc...)

    // For brevity, continue to next part...
    // Will continue in Part 2 (due to response size limits)
    return true;
  };

  #getRealmUrl = (): string | undefined => {
    if (typeof this.authServerUrl !== "undefined") {
      return (
        this.authServerUrl.replace(/\/$/, "") +
        "/realms/" +
        encodeURIComponent(this.realm)
      );
    }
    return undefined;
  };

  #processCallback = (
    oauth: Record<string, any>,
    setSuccess: (v?: unknown) => void,
    setError: (v?: unknown) => void,
  ): void => {
    const code = oauth.code;
    const error = oauth.error;
    const prompt = oauth.prompt;
    let timeLocal = Date.now();

    const authSuccess = (
      accessToken: string,
      refreshToken?: string,
      idToken?: string,
      fulfill?: boolean,
    ): void => {
      timeLocal = (timeLocal + Date.now()) / 2;
      this.#setToken(
        accessToken,
        refreshToken ?? undefined,
        idToken ?? undefined,
        timeLocal,
      );
      if (
        this.#useNonce &&
        this.idTokenParsed &&
        this.idTokenParsed.nonce !== oauth.storedNonce
      ) {
        if (this.enableLogging)
          console.info("[KEYCLOAK] Invalid nonce, clearing token");
        this.clearToken();
        setError();
      } else if (fulfill) {
        if (this.onAuthSuccess) this.onAuthSuccess();
        setSuccess();
      }
    };

    if (oauth["kc_action_status"] && this.onActionUpdate) {
      this.onActionUpdate(oauth["kc_action_status"], oauth["kc_action"]);
    }
    if (error) {
      if (prompt !== "none") {
        if (oauth.error_description === "authentication_expired") {
          this.login(oauth.loginOptions);
        } else {
          const errorData = {
            error,
            error_description: oauth.error_description,
          };
          if (this.onAuthError) this.onAuthError(errorData);
          setError(errorData);
        }
      } else {
        setSuccess();
      }
      return;
    }
    if (this.flow !== "standard" && (oauth.access_token || oauth.id_token))
      authSuccess(oauth.access_token, undefined, oauth.id_token, true);

    if (this.flow !== "implicit" && code) {
      this.#fetchAccessToken(
        this.endpoints.token(),
        code,
        this.clientId,
        decodeURIComponent(oauth.redirectUri),
        oauth.pkceCodeVerifier,
      )
        .then((response) => {
          authSuccess(
            response.access_token,
            response.refresh_token,
            response.id_token,
            this.flow === "standard",
          );
          this.scheduleCheckIframe();
        })
        .catch((error) => {
          if (this.onAuthError) this.onAuthError();
          setError(error);
        });
    }
  };

  #setToken = (
    token?: string,
    refreshToken?: string,
    idToken?: string,
    timeLocal?: number,
  ): void => {
    if (this.#tokenTimeoutHandle) {
      clearTimeout(this.#tokenTimeoutHandle);
      this.#tokenTimeoutHandle = undefined;
    }
    if (refreshToken) {
      this.refreshToken = refreshToken;
      this.refreshTokenParsed = decodeToken(refreshToken);
    } else {
      this.refreshToken = undefined;
      this.refreshTokenParsed = undefined;
    }
    if (idToken) {
      this.idToken = idToken;
      this.idTokenParsed = decodeToken(idToken);
    } else {
      this.idToken = undefined;
      this.idTokenParsed = undefined;
    }
    if (token) {
      this.token = token;
      this.tokenParsed = decodeToken(token);
      this.sessionId =
        (this.tokenParsed?.sid as string | undefined) ?? undefined;
      this.authenticated = true;
      this.subject = this.tokenParsed?.sub as string | undefined;
      this.realmAccess = this.tokenParsed?.realm_access as
        | { roles: string[] }
        | undefined;
      this.resourceAccess = this.tokenParsed?.resource_access as
        | Record<string, { roles: string[] }>
        | undefined;
      if (timeLocal && this.tokenParsed?.iat) {
        this.timeSkew =
          Math.floor(timeLocal / 1000) - (this.tokenParsed.iat as number);
      }
      if (this.timeSkew !== undefined && this.onTokenExpired) {
        const expiresIn =
          ((this.tokenParsed.exp as number) -
            Date.now() / 1000 +
            this.timeSkew) *
          1000;
        if (this.enableLogging)
          console.info(
            `[KEYCLOAK] Token expires in ${Math.round(expiresIn / 1000)} s`,
          );
        if (expiresIn <= 0) {
          this.onTokenExpired();
        } else {
          this.#tokenTimeoutHandle = window.setTimeout(
            () => this.onTokenExpired?.(),
            expiresIn,
          );
        }
      }
    } else {
      this.token = undefined;
      this.tokenParsed = undefined;
      this.sessionId = undefined;
      this.subject = undefined;
      this.realmAccess = undefined;
      this.resourceAccess = undefined;
      this.authenticated = false;
    }
  };

  #loadConfig = async (): Promise<void> => {
    if (typeof this.#config === "string") {
      const config = await fetchJSON<IJsonConfig>(this.#config);
      this.authServerUrl = config["auth-server-url"];
      this.realm = config.realm;
      this.clientId = config.resource;
      this.endpoints = this.#defaultEndpoints();
    } else if ("oidcProvider" in this.#config && this.#config.oidcProvider) {
      const oidcConfig: IOpenIdProviderMetadata =
        typeof this.#config.oidcProvider === "string"
          ? await fetchJSON<IOpenIdProviderMetadata>(
              `${this.#config.oidcProvider.replace(/\/$/, "")}/.well-known/openid-configuration`,
            )
          : this.#config.oidcProvider;
      this.clientId = this.#config.clientId;
      this.endpoints = this.#oidcEndpoints(oidcConfig);
    } else {
      this.authServerUrl = this.#config.url;
      this.realm = this.#config.realm;
      this.clientId = this.#config.clientId;
      this.endpoints = this.#defaultEndpoints();
    }
  };

  #defaultEndpoints = (): IEndpoints => {
    const realmUrl = this.#getRealmUrl()!;
    return {
      authorize: () => `${realmUrl}/protocol/openid-connect/auth`,
      token: () => `${realmUrl}/protocol/openid-connect/token`,
      logout: () => `${realmUrl}/protocol/openid-connect/logout`,
      checkSessionIframe: () =>
        `${realmUrl}/protocol/openid-connect/login-status-iframe.html`,
      thirdPartyCookiesIframe: () =>
        `${realmUrl}/protocol/openid-connect/3p-cookies/step1.html`,
      register: () => `${realmUrl}/protocol/openid-connect/registrations`,
      userinfo: () => `${realmUrl}/protocol/openid-connect/userinfo`,
    };
  };

  #oidcEndpoints = (oidcConfig: IOpenIdProviderMetadata): IEndpoints => ({
    authorize: () => oidcConfig.authorization_endpoint,
    token: () => oidcConfig.token_endpoint,
    logout: () => {
      if (!oidcConfig.end_session_endpoint)
        throw new Error("Not supported by the OIDC server");
      return oidcConfig.end_session_endpoint;
    },
    checkSessionIframe: () => {
      if (!oidcConfig.check_session_iframe)
        throw new Error("Not supported by the OIDC server");
      return oidcConfig.check_session_iframe;
    },
    register: () => {
      throw new Error("Register not supported in OIDC mode");
    },
    userinfo: () => {
      if (!oidcConfig.userinfo_endpoint)
        throw new Error("Not supported by the OIDC server");
      return oidcConfig.userinfo_endpoint;
    },
    thirdPartyCookiesIframe: () => {
      throw new Error("Not supported by the OIDC server");
    },
  });

  #fetchAccessToken = async (
    url: string,
    code: string,
    clientId: string,
    redirectUri: string,
    pkceCodeVerifier?: string,
  ): Promise<IAccessTokenResponse> => {
    const body = new URLSearchParams([
      ["code", code],
      ["grant_type", "authorization_code"],
      ["client_id", clientId],
      ["redirect_uri", redirectUri],
    ]);
    if (pkceCodeVerifier) body.append("code_verifier", pkceCodeVerifier);
    return fetchJSON<IAccessTokenResponse>(url, {
      method: "POST",
      credentials: "include",
      body,
    });
  };

  #fetchRefreshToken = async (
    url: string,
    refreshToken: string,
    clientId: string,
  ): Promise<IAccessTokenResponse> => {
    const body = new URLSearchParams([
      ["grant_type", "refresh_token"],
      ["refresh_token", refreshToken],
      ["client_id", clientId],
    ]);
    return fetchJSON<IAccessTokenResponse>(url, {
      method: "POST",
      credentials: "include",
      body,
    });
  };

  // ---- Public Methods ----

  public login = async (options?: IKeycloakLoginOptions): Promise<void> => {
    await this.adapter.login(options);
  };

  public logout = async (options?: IKeycloakLogoutOptions): Promise<void> => {
    await this.adapter.logout(options);
  };

  public createLoginUrl = async (
    options?: IKeycloakLoginOptions,
  ): Promise<string> => {
    const state = randomUUID();
    const nonce = randomUUID();
    const redirectUri = this.adapter.redirectUri(options);
    const callbackState: ICallbackState = {
      state,
      nonce,
      redirectUri: encodeURIComponent(redirectUri),
      loginOptions: options,
    };

    if (options?.prompt) callbackState.prompt = options.prompt;

    const url =
      options?.action === "register"
        ? this.endpoints.register()
        : this.endpoints.authorize();

    let scope = options?.scope ?? this.scope ?? "";
    const scopeValues = scope.split(" ");
    if (!arrayHas(scopeValues, "openid")) scopeValues.unshift("openid");
    scope = scopeValues.join(" ");

    const params = new URLSearchParams([
      ["client_id", this.clientId],
      ["redirect_uri", redirectUri],
      ["state", state],
      ["response_mode", this.responseMode],
      ["response_type", this.responseType],
      ["scope", scope],
    ]);

    if (this.#useNonce) params.append("nonce", nonce);
    if (options?.prompt) params.append("prompt", options.prompt);
    if (typeof options?.maxAge === "number")
      params.append("max_age", options.maxAge.toString());
    if (options?.loginHint) params.append("login_hint", options.loginHint);
    if (options?.idpHint) params.append("kc_idp_hint", options.idpHint);
    if (options?.action && options.action !== "register")
      params.append("kc_action", options.action);
    if (options?.locale) params.append("ui_locales", options.locale);

    if (this.pkceMethod) {
      const codeVerifier = generateCodeVerifier(96);
      const pkceChallenge = await generatePkceChallenge(
        this.pkceMethod,
        codeVerifier,
      );
      callbackState.pkceCodeVerifier = codeVerifier;
      params.append("code_challenge", pkceChallenge);
      params.append("code_challenge_method", this.pkceMethod);
    }

    this.#callbackStorage.add(callbackState);
    return `${url}?${params.toString()}`;
  };

  public createLogoutUrl = (options?: IKeycloakLogoutOptions): string => {
    const logoutMethod = options?.logoutMethod ?? this.logoutMethod;
    const url = this.endpoints.logout();
    if (logoutMethod === "POST") return url;
    const params = new URLSearchParams([
      ["client_id", this.clientId],
      ["post_logout_redirect_uri", this.adapter.redirectUri(options)],
    ]);
    if (this.idToken) params.append("id_token_hint", this.idToken);
    return `${url}?${params.toString()}`;
  };

  public createRegisterUrl = async (
    options?: IKeycloakRegisterOptions,
  ): Promise<string> => {
    return this.createLoginUrl({ ...options, action: "register" });
  };

  public createAccountUrl = (options?: IKeycloakAccountOptions): string => {
    const url = this.#getRealmUrl();
    if (!url) throw new Error("Cannot create account URL, no realm URL");
    const params = new URLSearchParams([
      ["referrer", this.clientId],
      ["referrer_uri", this.adapter.redirectUri(options)],
    ]);
    return `${url}/account?${params.toString()}`;
  };

  public accountManagement = async (): Promise<void> => {
    await this.adapter.accountManagement();
  };

  public hasRealmRole = (role: string): boolean =>
    !!this.realmAccess?.roles?.includes(role);

  public hasResourceRole = (role: string, resource?: string): boolean =>
    !!this.resourceAccess?.[resource ?? this.clientId]?.roles?.includes(role);

  public loadUserProfile = async (): Promise<IKeycloakProfile> => {
    const realmUrl = this.#getRealmUrl();
    if (!realmUrl) throw new Error("Cannot load user profile; no realm URL");
    const url = `${realmUrl}/account`;
    const profile = await fetchJSON<IKeycloakProfile>(url, {
      headers: [buildAuthorizationHeader(this.token!)],
    });
    this.profile = profile;
    return profile;
  };

  public loadUserInfo = async (): Promise<Record<string, unknown>> => {
    const url = this.endpoints.userinfo();
    const userInfo = await fetchJSON<Record<string, unknown>>(url, {
      headers: [buildAuthorizationHeader(this.token!)],
    });
    this.userInfo = userInfo;
    return userInfo;
  };

  public isTokenExpired = (minValidity?: number): boolean => {
    if (!this.tokenParsed || (!this.refreshToken && this.flow !== "implicit"))
      throw new Error("Not authenticated");
    if (this.timeSkew == undefined) return true;
    let expiresIn =
      (this.tokenParsed["exp"] as number) -
      Math.ceil(Date.now() / 1000) +
      (this.timeSkew ?? 0);
    if (minValidity) {
      if (isNaN(minValidity)) throw new Error("Invalid minValidity");
      expiresIn -= minValidity;
    }
    return expiresIn < 0;
  };

  public updateToken = async (minValidity?: number): Promise<boolean> => {
    if (!this.refreshToken) throw new Error("No refreshToken");
    const validity = minValidity ?? 5;
    const needsRefresh =
      validity === -1 || !this.tokenParsed || this.isTokenExpired(validity);
    if (!needsRefresh) return false;
    this.#refreshQueue.push({ setSuccess: () => {}, setError: () => {} });
    if (this.#refreshQueue.length === 1) {
      try {
        const url = this.endpoints.token();
        let timeLocal = Date.now();
        const response = await this.#fetchRefreshToken(
          url,
          this.refreshToken,
          this.clientId,
        );
        timeLocal = (timeLocal + Date.now()) / 2;
        this.#setToken(
          response.access_token,
          response.refresh_token,
          response.id_token,
          timeLocal,
        );
        if (this.onAuthRefreshSuccess) this.onAuthRefreshSuccess();
        while (this.#refreshQueue.length > 0)
          this.#refreshQueue.pop()?.setSuccess(true);
        return true;
      } catch (error) {
        if (this.onAuthRefreshError) this.onAuthRefreshError();
        while (this.#refreshQueue.length > 0)
          this.#refreshQueue.pop()?.setError(error);
        throw error;
      }
    }
    return true;
  };

  public clearToken = (): void => {
    if (this.token) {
      this.#setToken(undefined, undefined, undefined);
      if (this.onAuthLogout) this.onAuthLogout();
      if ((this as any).loginRequired) this.login();
    }
  };

  setupCheckLoginIframe = async (): Promise<void> => {
    if (!this.#loginIframe.enable) return;
    if (this.#loginIframe.iframe) return;
    const iframe = document.createElement("iframe");
    this.#loginIframe.iframe = iframe;

    await new Promise<void>((resolve) => {
      iframe.onload = () => {
        const authUrl = this.endpoints.authorize();
        this.#loginIframe.iframeOrigin = authUrl.startsWith("/")
          ? window.location.origin
          : authUrl.substring(0, authUrl.indexOf("/", 8));
        resolve();
      };
      iframe.setAttribute("src", this.endpoints.checkSessionIframe());
      iframe.setAttribute(
        "sandbox",
        "allow-storage-access-by-user-activation allow-scripts allow-same-origin",
      );
      iframe.setAttribute("title", "keycloak-session-iframe");
      iframe.style.display = "none";
      document.body.appendChild(iframe);

      window.addEventListener("message", (event: MessageEvent) => {
        if (
          event.origin !== this.#loginIframe.iframeOrigin ||
          this.#loginIframe.iframe?.contentWindow !== event.source
        ) {
          return;
        }
        if (!["unchanged", "changed", "error"].includes(event.data as string)) {
          return;
        }
        if (event.data !== "unchanged") {
          this.clearToken();
        }
        const callbacks = [...this.#loginIframe.callbackList];
        this.#loginIframe.callbackList = [];
        for (const cb of callbacks) {
          if (event.data === "error") cb.setError();
          else cb.setSuccess(event.data === "unchanged");
        }
      });
    });
  };

  public scheduleCheckIframe = (): void => {
    if (!this.#loginIframe.enable) return;
    if (this.token) {
      setTimeout(async () => {
        const unchanged = await this.checkLoginIframe();
        if (unchanged) this.scheduleCheckIframe();
      }, this.#loginIframe.interval * 1000);
    }
  };

  public checkLoginIframe = async (): Promise<boolean> => {
    if (this.#loginIframe.iframe && this.#loginIframe.iframeOrigin) {
      const msg = `${this.clientId} ${this.sessionId ?? ""}`;
      return await new Promise<boolean>((resolve, reject) => {
        this.#loginIframe.callbackList.push({
          setSuccess: (v) => resolve(Boolean(v)),
          setError: () => reject(new Error("Iframe check failed")),
        });
        if (this.#loginIframe.callbackList.length === 1) {
          this.#loginIframe.iframe!.contentWindow!.postMessage(
            msg,
            this.#loginIframe.iframeOrigin!,
          );
        }
      });
    }
    return true;
  };

  public check3pCookiesSupported = async (): Promise<void> => {
    if (
      (this.#loginIframe.enable || this.silentCheckSsoRedirectUri) &&
      typeof this.endpoints.thirdPartyCookiesIframe === "function"
    ) {
      const iframe = document.createElement("iframe");
      iframe.setAttribute("src", this.endpoints.thirdPartyCookiesIframe());
      iframe.setAttribute(
        "sandbox",
        "allow-storage-access-by-user-activation allow-scripts allow-same-origin",
      );
      iframe.setAttribute("title", "keycloak-3p-check-iframe");
      iframe.style.display = "none";
      document.body.appendChild(iframe);
      await new Promise<void>((resolve) => {
        window.addEventListener(
          "message",
          (event: MessageEvent) => {
            if (iframe.contentWindow !== event.source) return;
            if (!["supported", "unsupported"].includes(event.data as string))
              return;
            if (event.data === "unsupported") {
              if (this.enableLogging) {
                console.warn(
                  "[KEYCLOAK] Your browser is blocking 3rd-party cookies, silent auth and session detection won't work.",
                );
              }
              this.#loginIframe.enable = false;
              if (this.silentCheckSsoFallback) {
                this.silentCheckSsoRedirectUri = undefined;
              }
            }
            document.body.removeChild(iframe);
            resolve();
          },
          { once: true },
        );
      });
    }
  };

  public parseCallback = (url: string): Record<string, any> | undefined => {
    const oauth = this.parseCallbackUrl(url);
    if (!oauth) return undefined;
    const oauthState = this.#callbackStorage.get(oauth.state);
    if (oauthState) {
      oauth.valid = true;
      oauth.redirectUri = oauthState.redirectUri;
      oauth.storedNonce = oauthState.nonce;
      oauth.prompt = oauthState.prompt;
      oauth.pkceCodeVerifier = oauthState.pkceCodeVerifier;
      oauth.loginOptions = oauthState.loginOptions;
    }
    return oauth;
  };

  public parseCallbackUrl = (url: string): Record<string, any> | undefined => {
    let supportedParams: string[];
    switch (this.flow) {
      case "standard":
        supportedParams = [
          "code",
          "state",
          "session_state",
          "kc_action_status",
          "kc_action",
          "iss",
        ];
        break;
      case "implicit":
        supportedParams = [
          "access_token",
          "token_type",
          "id_token",
          "state",
          "session_state",
          "expires_in",
          "kc_action_status",
          "kc_action",
          "iss",
        ];
        break;
      case "hybrid":
        supportedParams = [
          "access_token",
          "token_type",
          "id_token",
          "code",
          "state",
          "session_state",
          "expires_in",
          "kc_action_status",
          "kc_action",
          "iss",
        ];
        break;
      default:
        supportedParams = [];
    }
    supportedParams.push("error", "error_description", "error_uri");

    const queryIndex = url.indexOf("?");
    const fragmentIndex = url.indexOf("#");
    let newUrl: string | undefined;
    let parsed:
      | { paramsString: string; oauthParams: Record<string, string> }
      | undefined;

    if (this.responseMode === "query" && queryIndex !== -1) {
      newUrl = url.substring(0, queryIndex);
      parsed = this.parseCallbackParams(
        url.substring(
          queryIndex + 1,
          fragmentIndex !== -1 ? fragmentIndex : url.length,
        ),
        supportedParams,
      );
      if (parsed.paramsString) newUrl += "?" + parsed.paramsString;
      if (fragmentIndex !== -1) newUrl += url.substring(fragmentIndex);
    } else if (this.responseMode === "fragment" && fragmentIndex !== -1) {
      newUrl = url.substring(0, fragmentIndex);
      parsed = this.parseCallbackParams(
        url.substring(fragmentIndex + 1),
        supportedParams,
      );
      if (parsed.paramsString) newUrl += "#" + parsed.paramsString;
    }

    if (parsed && parsed.oauthParams) {
      if (
        (this.flow === "standard" || this.flow === "hybrid") &&
        (parsed.oauthParams.code || parsed.oauthParams.error) &&
        parsed.oauthParams.state
      ) {
        parsed.oauthParams.newUrl = newUrl!;
        return parsed.oauthParams;
      } else if (
        this.flow === "implicit" &&
        (parsed.oauthParams.access_token || parsed.oauthParams.error) &&
        parsed.oauthParams.state
      ) {
        parsed.oauthParams.newUrl = newUrl!;
        return parsed.oauthParams;
      }
    }
    return undefined;
  };

  public parseCallbackParams = (
    paramsString: string,
    supportedParams: string[],
  ): { paramsString: string; oauthParams: Record<string, string> } => {
    const p = paramsString.split("&");
    let paramsOut: string[] = [];
    let oauthParams: Record<string, string> = {};
    for (const pair of p) {
      const [key, ...valArr] = pair.split("=");
      const val = valArr.join("=");
      if (supportedParams.includes(key)) {
        oauthParams[key] = val;
      } else {
        paramsOut.push(`${key}=${val}`);
      }
    }
    return { paramsString: paramsOut.join("&"), oauthParams };
  };
}

export default Keycloak;
