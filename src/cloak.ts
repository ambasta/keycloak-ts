import { randomUUID } from "crypto";

import type {
  IAccessTokenResponse,
  IJsonConfig,
  IKeycloakAccountOptions,
  IKeycloakAdapter,
  KeycloakConfigObject,
  IKeycloakInitOptions,
  IKeycloakLoginOptions,
  IKeycloakLogoutOptions,
  IKeycloakProfile,
  IKeycloakRegisterOptions,
  IOpenIdProviderMetadata,
  KeycloakFlow,
  KeycloakResponseMode,
  IEndpoints,
} from "./types.ts";
import {
  buildClaimsParameter,
  decodeToken,
  applyTimeoutToPromise,
  isObject,
  stripTrailingSlash,
} from "./helpers.ts";
import { NetworkError } from "./error.ts";
import { createCallbackStorage } from "./storage.ts";
import { generateCodeVerifier, generatePkceChallenge } from "./pkce.ts";

const CONTENT_TYPE_JSON = "application/json";

const arrayHas = <T>(arr: readonly T[], val: T): boolean => arr.includes(val);

const buildAuthorizationHeader = (token: string): [string, string] => {
  if (!token) {
    throw new Error(
      "Unable to build authorization header, token is not set, make sure the user is authenticated.",
    );
  }
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

const defaultAdapter = (kc: Keycloak): IKeycloakAdapter => ({
  login: async (options?: IKeycloakLoginOptions) => {
    window.location.assign(await kc.createLoginUrl(options));
    return new Promise<void>(() => {});
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
    return new Promise<void>(() => {});
  },
  accountManagement: async () => {
    const accountUrl = kc.createAccountUrl();
    if (accountUrl) {
      window.location.href = accountUrl;
    } else {
      throw new Error("Not supported by the OIDC server");
    }
    return new Promise<void>(() => {});
  },
  redirectUri: (options?: { redirectUri?: string }) =>
    options?.redirectUri || kc.redirectUri || location.href,
});

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
  clientId!: string;
  realm!: string;
  authServerUrl?: string;

  authenticated = false;
  didInitialize = false;
  profile?: IKeycloakProfile;
  userInfo?: Record<string, unknown>;
  token?: string;
  refreshToken?: string;
  idToken?: string;
  tokenParsed?: Record<string, unknown>;
  refreshTokenParsed?: Record<string, unknown>;
  idTokenParsed?: Record<string, unknown>;
  sessionId?: string;
  subject?: string;
  realmAccess?: { roles: string[] };
  resourceAccess?: Record<string, { roles: string[] }>;
  timeSkew?: number;
  flow: KeycloakFlow = "standard";
  responseMode: KeycloakResponseMode = "fragment";
  responseType = "code";
  pkceMethod: "S256" | false = "S256";
  scope?: string;
  enableLogging = false;
  silentCheckSsoRedirectUri?: string | false;
  silentCheckSsoFallback = true;
  redirectUri?: string;
  logoutMethod: "GET" | "POST" = "GET";
  messageReceiveTimeout = 10000;

  endpoints!: IEndpoints;
  adapter!: IKeycloakAdapter;

  onReady?: (authenticated: boolean) => void;
  onAuthSuccess?: () => void;
  onAuthError?: (err?: unknown) => void;
  onActionUpdate?: (status: string, action: string) => void;
  onAuthRefreshSuccess?: () => void;
  onAuthRefreshError?: () => void;
  onAuthLogout?: () => void;
  onTokenExpired?: () => void;

  #config: KeycloakConfigObject | string;
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

  #onLoad?: IKeycloakInitOptions["onLoad"];
  #loginRequired = false;
  #logInfo = createLogger(console.info);
  #logWarn = createLogger(console.warn);

  constructor(config: KeycloakConfigObject | string) {
    this.#config = config;

    if (!(this instanceof Keycloak)) throw new Error("Must use new Keycloak()");

    if (typeof config !== "string" && !isObject(config)) {
      throw new Error(
        "The 'Keycloak' constructor must be provided with a configuration object, or a URL to a JSON configuration file.",
      );
    }

    if (isObject(config)) {
      const configObj = config as KeycloakConfigObject;
      const requiredProperties =
        "oidcProvider" in configObj && configObj.oidcProvider
          ? ["clientId"]
          : ["url", "realm", "clientId"];

      for (const property of requiredProperties) {
        if (!(configObj as Record<string, unknown>)[property]) {
          throw new Error(
            `The configuration object is missing the required '${property}' property.`,
          );
        }
      }
    }
    if (!globalThis.isSecureContext) {
      this.#logWarn(
        "[KEYCLOAK] Keycloak JS must be used in a 'secure context' to function properly as it relies on browser APIs that are otherwise not available.\n" +
          "Continuing to run your application insecurely will lead to unexpected behavior and breakage.\n\n" +
          "For more information see: https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts",
      );
    }
  }

  init = async (initOptions: IKeycloakInitOptions = {}): Promise<boolean> => {
    if (this.didInitialize)
      throw new Error("Keycloak instance already initialized");
    this.didInitialize = true;
    this.authenticated = false;

    this.adapter = defaultAdapter(this);

    if (typeof initOptions.useNonce !== "undefined")
      this.#useNonce = initOptions.useNonce;
    if (typeof initOptions.checkLoginIframe !== "undefined")
      this.#loginIframe.enable = initOptions.checkLoginIframe;
    if (initOptions.checkLoginIframeInterval)
      this.#loginIframe.interval = initOptions.checkLoginIframeInterval;
    if (initOptions.onLoad === "login-required") this.#loginRequired = true;
    if (initOptions.onLoad) this.#onLoad = initOptions.onLoad;
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

    await this.#loadConfig();
    await this.check3pCookiesSupported();
    await this.#processInit(initOptions);
    this.onReady?.(this.authenticated);
    return this.authenticated;
  };

  #processInit = async (initOptions: IKeycloakInitOptions): Promise<void> => {
    const callback = this.parseCallback(window.location.href);

    if (callback?.valid) {
      this.#logInfo("[KEYCLOAK] Processing callback from URL");
      if (callback.newUrl && typeof window !== "undefined" && window.history)
        window.history.replaceState(window.history.state, "", callback.newUrl);

      await this.setupCheckLoginIframe();
      try {
        const cbResult = await this.#processCallback(callback);

        if (cbResult.kcActionStatus && this.onActionUpdate) {
          this.onActionUpdate(cbResult.kcActionStatus, cbResult.kcAction!);
        }

        if (cbResult.isPromptNoneError) {
        } else {
          this.onAuthSuccess?.();
          if (this.#loginIframe.enable) {
            this.scheduleCheckIframe();
          }
        }
      } catch (error: any) {
        this.#logWarn("[KEYCLOAK] Error processing callback from URL:", error);

        if (
          error.error_description === "authentication_expired" &&
          error.loginOptions
        ) {
          this.#logInfo(
            "[KEYCLOAK] Authentication expired, attempting re-login.",
          );
          await this.login(error.loginOptions);

          return;
        }
        this.onAuthError?.(error);

        if (this.#onLoad) {
          await this.#handleOnLoad(initOptions);
        }
      }
      return;
    }

    if (initOptions.token && initOptions.refreshToken) {
      this.#logInfo(
        "[KEYCLOAK] Using token and refreshToken provided in initOptions",
      );
      this.#setToken(
        initOptions.token,
        initOptions.refreshToken,
        initOptions.idToken,
      );

      if (this.#loginIframe.enable) {
        await this.setupCheckLoginIframe();
        try {
          const unchanged = await this.checkLoginIframe();
          if (unchanged) {
            this.onAuthSuccess?.();
            this.scheduleCheckIframe();
          } else {
            this.#logInfo(
              "[KEYCLOAK] Login iframe check returned 'changed', token may have been cleared by iframe handler.",
            );

            if (this.authenticated) {
              this.onAuthSuccess?.();
              this.scheduleCheckIframe();
            } else {
              if (this.#onLoad) {
                await this.#handleOnLoad(initOptions);
              }
            }
          }
        } catch (iframeError) {
          this.#logWarn(
            "[KEYCLOAK] Error during checkLoginIframe with existing token:",
            iframeError,
          );

          if (this.#onLoad) {
            await this.#handleOnLoad(initOptions);
          } else {
            throw iframeError;
          }
        }
      } else {
        try {
          await this.updateToken(-1);
          this.onAuthSuccess?.();
        } catch (error) {
          this.#logWarn(
            "[KEYCLOAK] Error refreshing token with existing token:",
            error,
          );
          this.onAuthError?.(error);
          if (this.#onLoad) {
            await this.#handleOnLoad(initOptions);
          } else {
            throw error;
          }
        }
      }
      return;
    }

    if (this.#onLoad) {
      await this.#handleOnLoad(initOptions);
    }
  };

  #handleOnLoad = async (initOptions: IKeycloakInitOptions): Promise<void> => {
    this.#logInfo(
      `[KEYCLOAK] #handleOnLoad called with onLoad: ${this.#onLoad}`,
    );
    switch (this.#onLoad) {
      case "check-sso":
        if (this.#loginIframe.enable) {
          await this.setupCheckLoginIframe();
          try {
            const unchanged = await this.checkLoginIframe();
            if (!unchanged) {
              if (this.silentCheckSsoRedirectUri) {
                await this.#checkSsoSilently(initOptions);
              } else {
                await this.#doLogin(false, initOptions.locale);
              }
            } else {
              this.#logInfo(
                "[KEYCLOAK] check-sso: Login iframe check returned unchanged.",
              );
            }
          } catch (error) {
            this.#logWarn(
              "[KEYCLOAK] check-sso: Error during checkLoginIframe",
              error,
            );

            if (this.silentCheckSsoRedirectUri) {
              await this.#checkSsoSilently(initOptions);
            } else {
              await this.#doLogin(false, initOptions.locale);
            }
          }
        } else {
          if (this.silentCheckSsoRedirectUri) {
            await this.#checkSsoSilently(initOptions);
          } else {
            await this.#doLogin(false, initOptions.locale);
          }
        }
        break;
      case "login-required":
        await this.#doLogin(true, initOptions.locale);
        break;
      default:
        if (this.#onLoad) {
          throw new Error(`Invalid value for onLoad: ${this.#onLoad}`);
        }
        break;
    }
  };

  #doLogin = async (prompt: boolean, locale?: string): Promise<void> => {
    this.#logInfo(
      `[KEYCLOAK] #doLogin called with prompt: ${prompt}, locale: ${locale}`,
    );
    const loginOptions: IKeycloakLoginOptions = { locale };
    if (!prompt) {
      loginOptions.prompt = "none";
    }
    await this.login(loginOptions);
  };

  #checkSsoSilently = async (
    initOptions: IKeycloakInitOptions,
  ): Promise<void> => {
    this.#logInfo(
      `[KEYCLOAK] #checkSsoSilently called, locale: ${initOptions.locale}`,
    );
    if (!this.silentCheckSsoRedirectUri) {
      this.#logWarn(
        "[KEYCLOAK] silentCheckSsoRedirectUri is not configured. Skipping silent SSO check.",
      );
      return;
    }

    const iframe = document.createElement("iframe");
    const loginUrlOptions: IKeycloakLoginOptions = {
      prompt: "none",
      redirectUri: this.silentCheckSsoRedirectUri,
    };
    if (initOptions.locale) {
      loginUrlOptions.locale = initOptions.locale;
    }
    const src = await this.createLoginUrl(loginUrlOptions);

    iframe.setAttribute("src", src);
    iframe.setAttribute(
      "sandbox",
      "allow-storage-access-by-user-activation allow-scripts allow-same-origin",
    );
    iframe.setAttribute("title", "keycloak-silent-check-sso");
    iframe.style.display = "none";
    document.body.appendChild(iframe);

    let timeoutHandle: number | undefined;

    const promise = new Promise<void>((resolve, reject) => {
      const messageCallback = async (event: MessageEvent) => {
        if (
          event.origin !== window.location.origin ||
          iframe.contentWindow !== event.source ||
          typeof event.data !== "string"
        ) {
          return;
        }

        if (timeoutHandle) {
          window.clearTimeout(timeoutHandle);
          timeoutHandle = undefined;
        }

        window.removeEventListener("message", messageCallback);
        document.body.removeChild(iframe);

        const oauth = this.parseCallback(event.data);
        if (oauth?.valid) {
          try {
            const cbResult = await this.#processCallback(oauth);

            if (cbResult.kcActionStatus && this.onActionUpdate) {
              this.onActionUpdate(cbResult.kcActionStatus, cbResult.kcAction!);
            }

            if (cbResult.isPromptNoneError) {
              this.#logInfo(
                "[KEYCLOAK] Silent SSO check resulted in a prompt=none error response.",
              );
            } else {
              this.onAuthSuccess?.();
            }
            resolve();
          } catch (error: any) {
            this.#logWarn(
              "[KEYCLOAK] Error processing silent SSO callback:",
              error,
            );
            this.onAuthError?.(error);
            reject(error);
          }
        } else {
          const errorData = {
            error: "invalid_sso_callback",
            error_description: "Callback from silent SSO iframe was not valid.",
          };
          this.#logWarn(
            "[KEYCLOAK] Invalid callback from silent SSO iframe",
            oauth,
          );
          this.onAuthError?.(errorData);
          reject(errorData);
        }
      };

      window.addEventListener("message", messageCallback, false);

      timeoutHandle = window.setTimeout(() => {
        window.removeEventListener("message", messageCallback);
        document.body.removeChild(iframe);
        this.#logWarn(
          "[KEYCLOAK] Timeout waiting for silent SSO iframe message.",
        );
        reject({ error: "Timeout_waiting_for_silent_SSO_iframe" });
      }, this.messageReceiveTimeout);
    });

    return await promise;
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

  #processCallback = async (
    oauth: Record<string, any>,
  ): Promise<{
    kcActionStatus?: string;
    kcAction?: string;
    prompt?: string;
    loginOptions?: IKeycloakLoginOptions;
    isPromptNoneError?: boolean;
  }> => {
    const code = oauth.code as string | undefined;
    const error = oauth.error as string | undefined;
    const prompt = oauth.prompt as string | undefined;
    const loginOptions = oauth.loginOptions as
      | IKeycloakLoginOptions
      | undefined;
    let timeLocal = Date.now();

    const _handleTokenResponse = (
      accessToken?: string,
      refreshToken?: string,
      idToken?: string,
      isImplicitOrHybridSuccess = false,
    ): void => {
      if (!isImplicitOrHybridSuccess) {
        timeLocal = (timeLocal + Date.now()) / 2;
      }

      this.#setToken(accessToken, refreshToken, idToken, timeLocal);

      if (this.#useNonce && this.idTokenParsed?.nonce !== oauth.storedNonce) {
        this.#logInfo("[KEYCLOAK] Invalid nonce, clearing token");
        this.clearToken();
        throw { error: "invalid_nonce", error_description: "Invalid nonce" };
      }
    };

    const result: {
      kcActionStatus?: string;
      kcAction?: string;
      prompt?: string;
      loginOptions?: IKeycloakLoginOptions;
      isPromptNoneError?: boolean;
    } = { prompt, loginOptions };

    if (oauth["kc_action_status"]) {
      result.kcActionStatus = oauth["kc_action_status"] as string;
      result.kcAction = oauth["kc_action"] as string;
    }

    if (error) {
      if (prompt === "none") {
        result.isPromptNoneError = true;
        return result;
      }
      const errorData = {
        error,
        error_description: oauth.error_description as string | undefined,
        error_uri: oauth.error_uri as string | undefined,
        prompt,
        loginOptions,
      };
      throw errorData;
    }

    if (this.flow !== "standard" && (oauth.access_token || oauth.id_token)) {
      _handleTokenResponse(
        oauth.access_token as string,
        oauth.refresh_token as string | undefined,
        oauth.id_token as string,
        true,
      );
      return result;
    }

    if (this.flow !== "implicit" && code) {
      timeLocal = Date.now();
      const response = await this.#fetchAccessToken(
        this.endpoints.token(),
        code,
        this.clientId,
        decodeURIComponent(oauth.redirectUri as string),
        oauth.pkceCodeVerifier as string | undefined,
      );

      _handleTokenResponse(
        response.access_token,
        response.refresh_token,
        response.id_token,
        false,
      );
      return result;
    }

    this.#logWarn(
      "[KEYCLOAK] #processCallback: No actionable parameters in callback.",
    );
    return result;
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
        if (this.enableLogging) {
          this.#logInfo(
            `[KEYCLOAK] Estimated time difference between browser and server is ${this.timeSkew} seconds`,
          );
          this.#logInfo(
            `[KEYCLOAK] Token expires in ${Math.round(expiresIn / 1000)} s`,
          );
        }
        if (expiresIn <= 0) {
          this.onTokenExpired?.();
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
      const jsonConfig = await fetchJSON<IJsonConfig>(this.#config);
      this.authServerUrl = jsonConfig["auth-server-url"];
      this.realm = jsonConfig.realm;

      this.clientId = jsonConfig.resource;
      this.endpoints = this.#defaultEndpoints();
    } else {
      const configObject = this.#config as KeycloakConfigObject;
      if (configObject.oidcProvider) {
        this.clientId = configObject.clientId;
        let oidcMetadata: IOpenIdProviderMetadata;
        if (typeof configObject.oidcProvider === "string") {
          const oidcDiscoveryUrl = `${stripTrailingSlash(configObject.oidcProvider)}/.well-known/openid-configuration`;
          oidcMetadata =
            await fetchJSON<IOpenIdProviderMetadata>(oidcDiscoveryUrl);
        } else {
          oidcMetadata = configObject.oidcProvider;
        }
        this.endpoints = this.#oidcEndpoints(oidcMetadata);
      } else {
        this.authServerUrl = configObject.url;
        this.realm = configObject.realm!;
        this.clientId = configObject.clientId;
        this.endpoints = this.#defaultEndpoints();
      }
    }
  };

  #defaultEndpoints = (): IEndpoints => {
    const realmUrl = this.#getRealmUrl();
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

  #oidcEndpoints = (oidcConfig: IOpenIdProviderMetadata): IEndpoints => {
    return {
      authorize: () => oidcConfig.authorization_endpoint,
      token: () => oidcConfig.token_endpoint,
      logout: () => {
        if (!oidcConfig.end_session_endpoint) {
          throw new Error("Not supported by the OIDC server");
        }
        return oidcConfig.end_session_endpoint;
      },
      checkSessionIframe: () => {
        if (!oidcConfig.check_session_iframe) {
          throw new Error("Not supported by the OIDC server");
        }
        return oidcConfig.check_session_iframe;
      },
      register: () => {
        throw new Error(
          'Redirection to "Register user" page not supported in standard OIDC mode',
        );
      },
      userinfo: () => {
        if (!oidcConfig.userinfo_endpoint) {
          throw new Error("Not supported by the OIDC server");
        }
        return oidcConfig.userinfo_endpoint;
      },
      thirdPartyCookiesIframe: () => {
        throw new Error("Not supported by the OIDC server");
      },
    };
  };

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

  login = async (options?: IKeycloakLoginOptions): Promise<void> => {
    await this.adapter.login(options);
  };

  logout = async (options?: IKeycloakLogoutOptions): Promise<void> => {
    await this.adapter.logout(options);
  };

  createLoginUrl = async (options?: IKeycloakLoginOptions): Promise<string> => {
    const state = randomUUID();
    const nonce = randomUUID();
    const redirectUri = this.adapter.redirectUri(options);

    const callbackState: import("./types.ts").ICallbackState = {
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

    if (options?.acr) {
      params.append("claims", buildClaimsParameter(options.acr));
    }
    if (options?.acrValues) {
      params.append("acr_values", options.acrValues);
    }

    if (this.pkceMethod) {
      const codeVerifier = generateCodeVerifier(96);
      const pkceChallenge = await generatePkceChallenge(codeVerifier);
      callbackState.pkceCodeVerifier = codeVerifier;
      params.append("code_challenge", pkceChallenge);
      params.append("code_challenge_method", this.pkceMethod);
    }

    this.#callbackStorage.add(callbackState);
    return `${url}?${params.toString()}`;
  };

  createLogoutUrl = (options?: IKeycloakLogoutOptions): string => {
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

  createRegisterUrl = async (
    options?: IKeycloakRegisterOptions,
  ): Promise<string> => {
    return this.createLoginUrl({ ...options, action: "register" });
  };

  createAccountUrl = (options?: IKeycloakAccountOptions): string => {
    const url = this.#getRealmUrl();
    if (!url) {
      throw new Error(
        "Unable to create account URL, make sure the adapter is not configured using a generic OIDC provider.",
      );
    }
    const params = new URLSearchParams([
      ["referrer", this.clientId],
      ["referrer_uri", this.adapter.redirectUri(options)],
    ]);
    return `${url}/account?${params.toString()}`;
  };

  accountManagement = async (): Promise<void> => {
    await this.adapter.accountManagement();
  };

  hasRealmRole = (role: string): boolean =>
    !!this.realmAccess?.roles?.includes(role);

  hasResourceRole = (role: string, resource?: string): boolean =>
    !!this.resourceAccess?.[resource ?? this.clientId]?.roles?.includes(role);

  loadUserProfile = async (): Promise<IKeycloakProfile> => {
    const realmUrl = this.#getRealmUrl();
    if (!realmUrl) throw new Error("Cannot load user profile; no realm URL");
    const url = `${realmUrl}/account`;
    const profile = await fetchJSON<IKeycloakProfile>(url, {
      headers: [buildAuthorizationHeader(this.token!)],
    });
    this.profile = profile;
    return profile;
  };

  loadUserInfo = async (): Promise<Record<string, unknown>> => {
    const url = this.endpoints.userinfo();
    const userInfo = await fetchJSON<Record<string, unknown>>(url, {
      headers: [buildAuthorizationHeader(this.token!)],
    });
    this.userInfo = userInfo;
    return userInfo;
  };

  isTokenExpired = (minValidity?: number): boolean => {
    if (!this.tokenParsed || (!this.refreshToken && this.flow !== "implicit")) {
      throw new Error("Not authenticated");
    }

    if (this.timeSkew == undefined) {
      this.#logInfo(
        "[KEYCLOAK] Unable to determine if token is expired as timeskew is not set",
      );
      return true;
    }

    let expiresIn =
      (this.tokenParsed["exp"] as number) -
      Math.ceil(Date.now() / 1000) +
      this.timeSkew;

    if (minValidity) {
      if (isNaN(minValidity)) {
        throw new Error("Invalid minValidity");
      }
      expiresIn -= minValidity;
    }
    return expiresIn < 0;
  };

  updateToken = async (minValidity?: number): Promise<boolean> => {
    if (!this.refreshToken) {
      throw new Error("Unable to update token, no refresh token available.");
    }

    const M_VALIDITY = minValidity ?? 5;

    if (this.#loginIframe.enable) {
      try {
        await this.checkLoginIframe();
      } catch (iframeError) {
        this.#logWarn(
          "[KEYCLOAK] Failed to check login iframe during token update:",
          iframeError,
        );
      }
    }

    let shouldRefreshToken = false;
    if (M_VALIDITY === -1) {
      shouldRefreshToken = true;
      this.#logInfo("[KEYCLOAK] Refreshing token: forced refresh");
    } else if (!this.tokenParsed || this.isTokenExpired(M_VALIDITY)) {
      shouldRefreshToken = true;
      this.#logInfo("[KEYCLOAK] Refreshing token: token expired");
    }

    if (!shouldRefreshToken) {
      return false;
    }

    return new Promise<boolean>((resolve, reject) => {
      this.#refreshQueue.push({ resolve, reject });

      if (this.#refreshQueue.length === 1) {
        (async () => {
          try {
            const url = this.endpoints.token();
            let timeLocal = Date.now();
            const response = await this.#fetchRefreshToken(
              url,
              this.refreshToken!,
              this.clientId,
            );
            timeLocal = (timeLocal + Date.now()) / 2;
            this.#logInfo("[KEYCLOAK] Token refreshed");

            this.#setToken(
              response.access_token,
              response.refresh_token,
              response.id_token,
              timeLocal,
            );

            this.onAuthRefreshSuccess?.();
            this.#refreshQueue.forEach((req) => req.resolve(true));
            this.#refreshQueue = [];
          } catch (error: any) {
            this.#logWarn("[KEYCLOAK] Failed to refresh token");

            if (
              error instanceof NetworkError &&
              error.response?.status === 400
            ) {
              this.clearToken();
            }

            this.onAuthRefreshError?.();
            this.#refreshQueue.forEach((req) => req.reject(error));
            this.#refreshQueue = [];
          }
        })();
      }
    });
  };

  clearToken = (): void => {
    if (this.token) {
      this.#setToken(undefined, undefined, undefined);
      this.onAuthLogout?.();
      if (this.#loginRequired) {
        this.login();
      }
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

  scheduleCheckIframe = (): void => {
    if (!this.#loginIframe.enable) return;
    if (this.token) {
      setTimeout(async () => {
        const unchanged = await this.checkLoginIframe();
        if (unchanged) this.scheduleCheckIframe();
      }, this.#loginIframe.interval * 1000);
    }
  };

  checkLoginIframe = async (): Promise<boolean> => {
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

  check3pCookiesSupported = async (): Promise<void> => {
    if (
      (!this.#loginIframe.enable && !this.silentCheckSsoRedirectUri) ||
      typeof this.endpoints.thirdPartyCookiesIframe !== "function"
    ) {
      return;
    }

    const iframe = document.createElement("iframe");
    iframe.setAttribute("src", this.endpoints.thirdPartyCookiesIframe());
    iframe.setAttribute(
      "sandbox",
      "allow-storage-access-by-user-activation allow-scripts allow-same-origin",
    );
    iframe.setAttribute("title", "keycloak-3p-check-iframe");
    iframe.style.display = "none";
    document.body.appendChild(iframe);

    const promise = new Promise<void>((resolve) => {
      const messageCallback = (event: MessageEvent) => {
        if (iframe.contentWindow !== event.source) {
          return;
        }

        if (event.data !== "supported" && event.data !== "unsupported") {
          return;
        }

        if (event.data === "unsupported") {
          this.#logWarn(
            "[KEYCLOAK] Your browser is blocking access to 3rd-party cookies, this means:\n\n" +
              " - It is not possible to retrieve tokens without redirecting to the Keycloak server (a.k.a. no support for silent authentication).\n" +
              " - It is not possible to automatically detect changes to the session status (such as the user logging out in another tab).\n\n" +
              "For more information see: https://www.keycloak.org/securing-apps/javascript-adapter#_modern_browsers",
          );
          this.#loginIframe.enable = false;
          if (this.silentCheckSsoFallback) {
            this.silentCheckSsoRedirectUri = false;
          }
        }

        document.body.removeChild(iframe);
        window.removeEventListener("message", messageCallback);
        resolve();
      };

      window.addEventListener("message", messageCallback, false);
    });

    try {
      await applyTimeoutToPromise(
        promise,
        this.messageReceiveTimeout,
        "Timeout when waiting for 3rd party check iframe message.",
      );
    } catch (error) {
      this.#logWarn("[KEYCLOAK] Error during 3rd party cookie check:", error);
    }
  };

  parseCallback = (url: string): Record<string, any> | undefined => {
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

  parseCallbackUrl = (url: string): Record<string, any> | undefined => {
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

  parseCallbackParams = (
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
