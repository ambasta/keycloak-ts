import { randomUUID } from "crypto";

import type {
  IAccessTokenResponse,
  IJsonConfig,
  IKeycloakAccountOptions,
  IKeycloakAdapter,
  KeycloakConfigObject, // Updated type
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
  buildClaimsParameter, // Added import
  decodeToken,
  applyTimeoutToPromise, // Added import
  isObject,
  sha256Digest,
  stripTrailingSlash, 
  type IEndpoints,
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

// ICallbackState has been moved to src/types.ts

const defaultAdapter = (kc: Keycloak): IKeycloakAdapter => ({
  login: async (options?: IKeycloakLoginOptions) => {
    window.location.assign(await kc.createLoginUrl(options));
    return new Promise<void>(() => {}); // Add unresolved promise
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
    return new Promise<void>(() => {}); // Add unresolved promise
  },
  accountManagement: async () => { // Make async to return a Promise
    const accountUrl = kc.createAccountUrl();
    if (accountUrl) {
      window.location.href = accountUrl;
    } else {
      throw new Error("Not supported by the OIDC server");
    }
    return new Promise<void>(() => {}); // Add unresolved promise
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
  public silentCheckSsoRedirectUri?: string | false; // Allow false
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
  #config: KeycloakConfigObject | string; // Updated type
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

  // New private fields for init options and logging
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
      // Type guard to assert config is KeycloakConfigObject for property checking
      const configObj = config as KeycloakConfigObject;
      const requiredProperties =
        "oidcProvider" in configObj && configObj.oidcProvider // Check if oidcProvider is truthy
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
      this.#loginRequired = true; // Use private field
    if (initOptions.onLoad) {
      this.#onLoad = initOptions.onLoad; // Store onLoad option
    }
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

    // --- START OF NEW INIT LOGIC STRUCTURE ---
    await this.#loadConfig(); // Already called and refactored.
    await this.check3pCookiesSupported();
    await this.#processInit(initOptions);
    this.onReady?.(this.authenticated);
    return this.authenticated;
    // --- END OF NEW INIT LOGIC STRUCTURE ---
  };

  // Stubs for new private methods - implementation will follow in subsequent steps
  #processInit = async (initOptions: IKeycloakInitOptions): Promise<void> => {
    const callback = this.parseCallback(window.location.href);

    if (callback?.valid) {
      this.#logInfo("[KEYCLOAK] Processing callback from URL");
      if (callback.newUrl && typeof window !== "undefined" && window.history) {
        window.history.replaceState(window.history.state, null, callback.newUrl);
      }
      await this.setupCheckLoginIframe();
      try {
        const cbResult = await this.#processCallback(callback);
        
        if (cbResult.kcActionStatus && this.onActionUpdate) {
          this.onActionUpdate(cbResult.kcActionStatus, cbResult.kcAction!);
        }

        if (cbResult.isPromptNoneError) {
          // Error handled silently for prompt=none, no tokens set.
          // No onAuthSuccess, no onAuthError from this path explicitly here.
          // The 'authenticated' flag remains as is (likely false).
          // If #onLoad is present, it might be processed later.
        } else {
          // Success path (tokens set, nonce OK by #processCallback)
          this.onAuthSuccess?.();
          if (this.#loginIframe.enable) {
            this.scheduleCheckIframe();
          }
        }
      } catch (error: any) {
        this.#logWarn("[KEYCLOAK] Error processing callback from URL:", error);
        // Check for authentication_expired to attempt re-login
        if (error.error_description === "authentication_expired" && error.loginOptions) {
          this.#logInfo("[KEYCLOAK] Authentication expired, attempting re-login.");
          await this.login(error.loginOptions); // This will redirect
          // Normally, execution stops here due to redirect.
          // To be extremely safe in a non-browser env or if redirect is delayed:
          return; // Stop further processing in #processInit
        }
        this.onAuthError?.(error); // Emit error for other cases
        // If there was an error, and onLoad is set, it might trigger subsequent actions
        if (this.#onLoad) {
          await this.#handleOnLoad(initOptions);
        }
      }
      return; // Callback processed or error handled (including potential redirect)
    }

    if (initOptions.token && initOptions.refreshToken) {
      this.#logInfo("[KEYCLOAK] Using token and refreshToken provided in initOptions");
      this.#setToken(initOptions.token, initOptions.refreshToken, initOptions.idToken);

      if (this.#loginIframe.enable) {
        await this.setupCheckLoginIframe();
        try {
          const unchanged = await this.checkLoginIframe();
          if (unchanged) {
            this.onAuthSuccess?.();
            this.scheduleCheckIframe();
          } else {
            // Token state might have changed, lib/keycloak.js behavior is nuanced here.
            // It doesn't explicitly clearToken but relies on checkLoginIframe's message handler.
            // For now, if not unchanged, it implies a potential state mismatch.
            // Depending on strictness, one might clearToken or try to refresh.
            // lib/keycloak.js proceeds to onAuthSuccess if checkLoginIframe doesn't error.
            // The 'changed' message in checkLoginIframe's handler *does* clearToken.
            // Assuming checkLoginIframe itself would throw or its handler clears token if problematic.
            // If it resolves, and was 'changed', token is already cleared.
            // If it resolved 'unchanged', then onAuthSuccess is correct.
            // If checkLoginIframe threw, it's caught below.
             this.#logInfo("[KEYCLOAK] Login iframe check returned 'changed', token may have been cleared by iframe handler.");
             // If token was cleared, authenticated would be false.
             // If not cleared, onAuthSuccess is fine.
             if (this.authenticated) {
                this.onAuthSuccess?.();
                this.scheduleCheckIframe();
             } else {
                // Token was cleared by iframe's 'changed' message, effectively a silent logout
                // If loginRequired, this might trigger a new login via #handleOnLoad
                if (this.#onLoad) {
                    await this.#handleOnLoad(initOptions);
                }
             }
          }
        } catch (iframeError) {
            this.#logWarn("[KEYCLOAK] Error during checkLoginIframe with existing token:", iframeError);
            // Similar to updateToken error, decide if #handleOnLoad or rethrow
            if (this.#onLoad) {
                await this.#handleOnLoad(initOptions);
            } else {
                throw iframeError; // Rethrow if onLoad not set to handle it
            }
        }
      } else { // loginIframe disabled
        try {
          await this.updateToken(-1); // Force refresh
          this.onAuthSuccess?.();
        } catch (error) {
          this.#logWarn("[KEYCLOAK] Error refreshing token with existing token:", error);
          this.onAuthError?.(error);
          if (this.#onLoad) {
            await this.#handleOnLoad(initOptions);
          } else {
            throw error; // Rethrow if onLoad not set to handle it
          }
        }
      }
      return; // Tokens from initOptions processed
    }

    if (this.#onLoad) {
      await this.#handleOnLoad(initOptions);
    }
  };

  #handleOnLoad = async (initOptions: IKeycloakInitOptions): Promise<void> => {
    this.#logInfo(`[KEYCLOAK] #handleOnLoad called with onLoad: ${this.#onLoad}`);
    switch (this.#onLoad) {
      case "check-sso":
        if (this.#loginIframe.enable) {
          await this.setupCheckLoginIframe();
          try {
            const unchanged = await this.checkLoginIframe();
            if (!unchanged) {
              // Token state changed or needs verification
              if (this.silentCheckSsoRedirectUri) {
                await this.#checkSsoSilently(initOptions);
              } else {
                await this.#doLogin(false, initOptions.locale); // prompt=false
              }
            } else {
              // If unchanged, and we have a token, it implies SSO is working.
              // If no token, it means user is not logged in via SSO.
              // lib/keycloak.js doesn't explicitly emit onAuthSuccess here,
              // it's usually emitted after a token is obtained/validated.
              // If checkLoginIframe indicates 'unchanged' with existing valid token, onAuthSuccess was already called.
              // If 'unchanged' with no token, then nothing to do, user is not logged in.
              this.#logInfo("[KEYCLOAK] check-sso: Login iframe check returned unchanged.");
            }
          } catch (error) {
            this.#logWarn("[KEYCLOAK] check-sso: Error during checkLoginIframe", error);
            // Fallback to login or silent check on error
            if (this.silentCheckSsoRedirectUri) {
              await this.#checkSsoSilently(initOptions);
            } else {
              await this.#doLogin(false, initOptions.locale);
            }
          }
        } else { // loginIframe disabled
          if (this.silentCheckSsoRedirectUri) {
            await this.#checkSsoSilently(initOptions);
          } else {
            await this.#doLogin(false, initOptions.locale);
          }
        }
        break;
      case "login-required":
        await this.#doLogin(true, initOptions.locale); // prompt=true
        break;
      default:
        // This case should ideally not be reached if #onLoad is validated.
        // If #onLoad is undefined, this method should not have been called.
        if (this.#onLoad) { // Only throw if #onLoad had an unexpected value
          throw new Error(`Invalid value for onLoad: ${this.#onLoad}`);
        }
        break;
    }
  };

  #doLogin = async (prompt: boolean, locale?: string): Promise<void> => {
    // Placeholder for logic from lib/keycloak.js's doLogin()
    this.#logInfo(`[KEYCLOAK] #doLogin called with prompt: ${prompt}, locale: ${locale}`);
    const loginOptions: IKeycloakLoginOptions = { locale };
    if (!prompt) {
      loginOptions.prompt = "none";
    }
    await this.login(loginOptions);
  };

  #checkSsoSilently = async (initOptions: IKeycloakInitOptions): Promise<void> => {
    this.#logInfo(`[KEYCLOAK] #checkSsoSilently called, locale: ${initOptions.locale}`);
    if (!this.silentCheckSsoRedirectUri) {
      this.#logWarn("[KEYCLOAK] silentCheckSsoRedirectUri is not configured. Skipping silent SSO check.");
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
    iframe.setAttribute("sandbox", "allow-storage-access-by-user-activation allow-scripts allow-same-origin");
    iframe.setAttribute("title", "keycloak-silent-check-sso");
    iframe.style.display = "none";
    document.body.appendChild(iframe);

    let timeoutHandle: number | undefined;

    const promise = new Promise<void>((resolve, reject) => {
      const messageCallback = async (event: MessageEvent) => {
        if (
          event.origin !== window.location.origin || // Check origin if iframe is on same origin
          iframe.contentWindow !== event.source || // Check source
          typeof event.data !== 'string' // Ensure data is a string (URL)
        ) {
          return;
        }

        // Clear timeout if message received
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
              // Error handled silently for prompt=none.
              // For silent SSO, this typically means no active session or user chose not to grant.
              this.#logInfo("[KEYCLOAK] Silent SSO check resulted in a prompt=none error response.");
            } else {
              // Success (tokens set, nonce OK by #processCallback)
              this.onAuthSuccess?.();
              // scheduleCheckIframe is usually not called after silent SSO by lib/keycloak.js,
              // as it's part of an ongoing session status check. The main scheduleCheckIframe loop would continue.
            }
            resolve();
          } catch (error: any) { // Catch errors from #processCallback (e.g., invalid_nonce)
            this.#logWarn("[KEYCLOAK] Error processing silent SSO callback:", error);
            this.onAuthError?.(error);
            reject(error);
          }
        } else {
          const errorData = { error: "invalid_sso_callback", error_description: "Callback from silent SSO iframe was not valid." };
          this.#logWarn("[KEYCLOAK] Invalid callback from silent SSO iframe", oauth);
          this.onAuthError?.(errorData);
          reject(errorData);
        }
      };

      window.addEventListener("message", messageCallback, false);

      timeoutHandle = window.setTimeout(() => {
        window.removeEventListener("message", messageCallback);
        document.body.removeChild(iframe);
        this.#logWarn("[KEYCLOAK] Timeout waiting for silent SSO iframe message.");
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

  #processCallback = async (oauth: Record<string, any>): Promise<{
    kcActionStatus?: string;
    kcAction?: string;
    prompt?: string; // Pass prompt through for decision making by caller
    loginOptions?: IKeycloakLoginOptions; // Pass loginOptions through
    isPromptNoneError?: boolean;
  }> => {
    const code = oauth.code as string | undefined;
    const error = oauth.error as string | undefined;
    const prompt = oauth.prompt as string | undefined; // From stored callback state
    const loginOptions = oauth.loginOptions as IKeycloakLoginOptions | undefined;
    let timeLocal = Date.now(); // Initial value, reset before async ops if averaged after

    const _handleTokenResponse = (
      accessToken?: string,
      refreshToken?: string,
      idToken?: string,
      isImplicitOrHybridSuccess = false,
    ): void => {
      if (!isImplicitOrHybridSuccess) { // For code flow, average time after async op
        timeLocal = (timeLocal + Date.now()) / 2;
      }
      // For implicit/hybrid, timeLocal is effectively Date.now() before this call.
      
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
        return result; // Resolve for prompt=none errors, caller decides action
      }
      const errorData = {
        error,
        error_description: oauth.error_description as string | undefined,
        error_uri: oauth.error_uri as string | undefined,
        prompt, // Include prompt in errorData for caller
        loginOptions, // Include loginOptions for caller
      };
      throw errorData; // Throw for non-prompt=none errors
    }

    // Implicit or Hybrid flow with tokens in URL
    if (this.flow !== "standard" && (oauth.access_token || oauth.id_token)) {
      _handleTokenResponse(
        oauth.access_token as string,
        oauth.refresh_token as string | undefined,
        oauth.id_token as string,
        true, 
      );
      return result;
    }

    // Standard or Hybrid flow with code
    if (this.flow !== "implicit" && code) {
      timeLocal = Date.now(); // Reset timeLocal *before* async #fetchAccessToken
      const response = await this.#fetchAccessToken(
        this.endpoints.token(),
        code,
        this.clientId,
        decodeURIComponent(oauth.redirectUri as string),
        oauth.pkceCodeVerifier as string | undefined,
      );
      // _handleTokenResponse will average timeLocal
      _handleTokenResponse(
        response.access_token,
        response.refresh_token,
        response.id_token,
        false,
      );
      return result;
    }
    
    // Should ideally not be reached if one of the above conditions is met.
    // If it is, it means no error, no tokens in URL, no code.
    this.#logWarn("[KEYCLOAK] #processCallback: No actionable parameters in callback.");
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
      // Case 1: Config is a string URL (path to keycloak.json)
      const jsonConfig = await fetchJSON<IJsonConfig>(this.#config);
      this.authServerUrl = jsonConfig["auth-server-url"];
      this.realm = jsonConfig.realm;
      // In lib/keycloak.js, 'resource' from JSON config is assigned to clientId
      this.clientId = jsonConfig.resource;
      this.endpoints = this.#defaultEndpoints();
    } else {
      // Config is an object (KeycloakConfigObject)
      const configObject = this.#config as KeycloakConfigObject;
      if (configObject.oidcProvider) {
        // Case 2: Object with oidcProvider
        this.clientId = configObject.clientId;
        let oidcMetadata: IOpenIdProviderMetadata;
        if (typeof configObject.oidcProvider === "string") {
          // oidcProvider is a URL, fetch discovery document
          const oidcDiscoveryUrl = `${stripTrailingSlash(configObject.oidcProvider)}/.well-known/openid-configuration`;
          oidcMetadata = await fetchJSON<IOpenIdProviderMetadata>(oidcDiscoveryUrl);
        } else {
          // oidcProvider is an object, use directly
          oidcMetadata = configObject.oidcProvider;
        }
        this.endpoints = this.#oidcEndpoints(oidcMetadata);
      } else {
        // Case 3: Object with url, realm, clientId
        // These properties are guaranteed by KeycloakConfigObject type and constructor checks
        this.authServerUrl = configObject.url;
        this.realm = configObject.realm!;
        this.clientId = configObject.clientId;
        this.endpoints = this.#defaultEndpoints();
      }
    }
  };

  #defaultEndpoints = (): IEndpoints => {
    const realmUrl = this.#getRealmUrl();
    // realmUrl is string | undefined. lib/keycloak.js allows it to be undefined here,
    // and errors would occur when an endpoint function is called.
    // For stricter safety, we could throw if !realmUrl, but matching JS behavior:
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
        // Matching the exact error message from lib/keycloak.js
        throw new Error('Redirection to "Register user" page not supported in standard OIDC mode');
      },
      userinfo: () => {
        if (!oidcConfig.userinfo_endpoint) {
          throw new Error("Not supported by the OIDC server");
        }
        return oidcConfig.userinfo_endpoint;
      },
      // This endpoint is not defined in OIDC discovery in lib/keycloak.js setupOidcEndpoints
      // Behavior in lib/keycloak.js is that kc.endpoints.thirdPartyCookiesIframe would be undefined.
      // Calling an undefined function throws. For defined behavior, we throw an error.
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
    // Ensure ICallbackState is imported if not already
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

    // Add acr and acr_values handling
    if (options?.acr) {
      params.append('claims', buildClaimsParameter(options.acr));
    }
    if (options?.acrValues) {
      params.append('acr_values', options.acrValues);
    }

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
    if (!this.tokenParsed || (!this.refreshToken && this.flow !== "implicit")) {
      throw new Error("Not authenticated");
    }

    if (this.timeSkew == undefined) {
      this.#logInfo("[KEYCLOAK] Unable to determine if token is expired as timeskew is not set");
      return true;
    }

    let expiresIn =
      (this.tokenParsed["exp"] as number) -
      Math.ceil(Date.now() / 1000) +
      this.timeSkew; // timeSkew is guaranteed to be a number here by the check above

    if (minValidity) {
      if (isNaN(minValidity)) {
        throw new Error("Invalid minValidity");
      }
      expiresIn -= minValidity;
    }
    return expiresIn < 0;
  };

  public updateToken = async (minValidity?: number): Promise<boolean> => {
    if (!this.refreshToken) {
      throw new Error("Unable to update token, no refresh token available.");
    }

    const M_VALIDITY = minValidity ?? 5; // Use a different name to avoid confusion with parameter

    if (this.#loginIframe.enable) {
      try {
        await this.checkLoginIframe();
      } catch (iframeError) {
        // Log error but continue, as per lib/keycloak.js which doesn't stop refresh for iframe error
        this.#logWarn("[KEYCLOAK] Failed to check login iframe during token update:", iframeError);
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
      return false; // No refresh needed
    }

    return new Promise<boolean>((resolve, reject) => {
      this.#refreshQueue.push({ resolve, reject });

      if (this.#refreshQueue.length === 1) {
        // This is the first request in the queue, so perform the refresh.
        (async () => {
          try {
            const url = this.endpoints.token();
            let timeLocal = Date.now();
            const response = await this.#fetchRefreshToken(
              url,
              this.refreshToken!, // refreshToken is checked at the beginning
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

            // Clear token if the error is a 400 response (e.g. invalid grant)
            if (error instanceof NetworkError && error.response?.status === 400) {
              this.clearToken();
            }

            this.onAuthRefreshError?.();
            this.#refreshQueue.forEach((req) => req.reject(error));
            this.#refreshQueue = [];
          }
        })();
      }
      // Else, the request is queued and will be resolved/rejected by the active refresh.
    });
  };

  public clearToken = (): void => {
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
    // Align precondition with lib/keycloak.js
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

        if (
          event.data !== "supported" &&
          event.data !== "unsupported"
        ) {
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
            this.silentCheckSsoRedirectUri = false; // Align with lib/keycloak.js
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
      // If timeout or other error, assume cookies might not be supported or detection failed.
      // Depending on desired strictness, could disable features here too.
      // lib/keycloak.js doesn't explicitly disable on timeout, but logs.
      // Current implementation: log and continue.
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
