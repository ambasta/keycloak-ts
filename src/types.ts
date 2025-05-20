// types.ts
export type KeycloakOnLoad = "login-required" | "check-sso";
export type KeycloakResponseMode = "query" | "fragment";
export type KeycloakResponseType =
  | "code"
  | "id_token token"
  | "code id_token token";
export type KeycloakFlow = "standard" | "implicit" | "hybrid";
export type KeycloakPkceMethod = "S256" | false;

// IAcr interface might be removed if not used elsewhere, or kept if it's for a different purpose.
// For createLoginUrl options.acr, it's a string.
/*
export interface IAcr {
  values: string[];
  essential: boolean;
}
*/

export interface IKeycloakConfig extends Record<string, unknown> {
  url: string;
  realm: string;
  clientId: string;
}

export interface IKeycloakInitOptions {
  useNonce?: boolean;
  adapter?: "default" | "cordova" | "cordova-native" | IKeycloakAdapter;
  onLoad?: KeycloakOnLoad;
  token?: string;
  refreshToken?: string;
  idToken?: string;
  timeSkew?: number;
  checkLoginIframe?: boolean;
  checkLoginIframeInterval?: number;
  responseMode?: KeycloakResponseMode;
  redirectUri?: string;
  silentCheckSsoRedirectUri?: string | false; // Allow false
  silentCheckSsoFallback?: boolean;
  flow?: KeycloakFlow;
  pkceMethod?: KeycloakPkceMethod;
  enableLogging?: boolean;
  scope?: string;
  messageReceiveTimeout?: number;
  locale?: string;
  logoutMethod?: "GET" | "POST";
}

export interface INetworkErrorOptions extends ErrorOptions {
  response: Response;
}

export interface IKeycloakLoginOptions {
  scope?: string;
  redirectUri?: string;
  prompt?: "none" | "login" | "consent";
  action?: string;
  maxAge?: number;
  loginHint?: string;
  acr?: string; // Changed from IAcr to string to match lib/keycloak.js options.acr
  acrValues?: string;
  idpHint?: string;
  locale?: string;
  cordovaOptions?: Record<string, string>;
}

export interface IKeycloakLogoutOptions {
  redirectUri?: string;
  logoutMethod?: "GET" | "POST";
}

export interface IKeycloakRegisterOptions
  extends Omit<IKeycloakLoginOptions, "action"> {}

export interface IKeycloakAccountOptions {
  redirectUri?: string;
}

export interface IKeycloakError {
  error: string;
  error_description: string;
}

export interface IKeycloakAdapter {
  login(options?: IKeycloakLoginOptions): Promise<void>;
  logout(options?: IKeycloakLogoutOptions): Promise<void>;
  register(options?: IKeycloakRegisterOptions): Promise<void>;
  accountManagement(): Promise<void>;
  redirectUri(options?: { redirectUri?: string }, encodeHash?: boolean): string;
}

export interface IKeycloakProfile {
  id?: string;
  username?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled?: boolean;
  emailVerified?: boolean;
  totp?: boolean;
  createdTimestamp?: number;
  attributes?: Record<string, unknown>;
}

export interface IKeycloakRoles {
  roles: string[];
}

export interface IKeycloakResourceAccess {
  [key: string]: IKeycloakRoles;
}

export interface IKeycloakTokenParsed {
  iss?: string;
  sub?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  auth_time?: number;
  nonce?: string;
  acr?: string;
  amr?: string;
  azp?: string;
  session_state?: string;
  realm_access?: IKeycloakRoles;
  resource_access?: IKeycloakResourceAccess;
  [key: string]: unknown;
}

export interface IOpenIdProviderMetadata extends Record<string, unknown> {
  issuer?: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
  check_session_iframe?: string;
  jwks_uri?: string;
  registration_endpoint?: string;
  introspection_endpoint?: string;
  revocation_endpoint?: string;
}

export interface IJsonConfig {
  "auth-server-url": string;
  realm: string;
  resource?: string;
  clientId?: string;
  url?: string;
  "auth-server-url": string;
  realm: string;
  resource: string; // In lib/keycloak.js, 'resource' is used for clientId from JSON file
}

// Represents the object that can be passed to the Keycloak constructor
export type KeycloakConfigObject =
  | {
      url: string; // Used if oidcProvider is not set
      realm: string; // Used if oidcProvider is not set
      clientId: string;
      oidcProvider?: never;
    }
  | {
      oidcProvider: string | IOpenIdProviderMetadata; // URL string or OIDC metadata object
      clientId: string;
      url?: never;
      realm?: never;
    };

export interface IAccessTokenResponse extends Record<string, unknown> {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
  session_state?: string;
}

// Moved from cloak.ts
export interface ICallbackState {
  state: string;
  nonce: string;
  redirectUri: string;
  // Assuming IKeycloakLoginOptions is available or will be imported if types.ts is separate
  loginOptions?: IKeycloakLoginOptions; // Make sure IKeycloakLoginOptions is defined/imported
  prompt?: string;
  pkceCodeVerifier?: string;
  expires?: number; // Used by LocalStorageStore for item expiry
}

export interface ICallbackStorage {
  get(state: string): ICallbackState | undefined;
  add(state: ICallbackState): void;
  removeItem?(key: string): void; // Optional as it's mainly for cookie management during clear all
}
