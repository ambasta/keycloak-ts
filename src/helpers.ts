// keycloak-helpers.ts
import type { IKeycloakTokenParsed } from "./types.js";

export interface IEndpoints {
  authorize(): string;
  token(): string;
  logout(): string;
  checkSessionIframe(): string;
  thirdPartyCookiesIframe(): string;
  register(): string;
  userinfo(): string;
}

export const isObject = (input: unknown): boolean =>
  typeof input === "object" && input !== null;

export const decodeToken = (token: string): IKeycloakTokenParsed => {
  const parts = token.split(".");
  const payload = parts[1]; // The payload is the second part

  if (typeof payload !== "string") {
    throw new Error("Unable to decode token, payload not found.");
  }

  let decoded: string;
  try {
    decoded = base64UrlDecode(payload);
  } catch (error: any) {
    throw new Error(
      "Unable to decode token, payload is not a valid Base64URL value.",
      { cause: error },
    );
  }

  try {
    return JSON.parse(decoded) as IKeycloakTokenParsed;
  } catch (error: any) {
    throw new Error(
      "Unable to decode token, payload is not a valid JSON value.",
      { cause: error },
    );
  }
};

const base64UrlDecode = (input: string): string => {
  let output = input.replaceAll("-", "+").replaceAll("_", "/");
  switch (output.length % 4) {
    case 0:
      break;
    case 2:
      output += "==";
      break;
    case 3:
      output += "=";
      break;
    default:
      throw new Error("Input is not of the correct length.");
  }
  try {
    return b64DecodeUnicode(output);
  } catch {
    return atob(output);
  }
};

const b64DecodeUnicode = (input: string): string => {
  return decodeURIComponent(
    atob(input).replace(/(.)/g, (_m, p) => {
      let code = p.charCodeAt(0).toString(16).toUpperCase();
      if (code.length < 2) code = "0" + code;
      return "%" + code;
    }),
  );
};

export const bytesToBase64 = (bytes: Uint8Array): string => {
  // Use String.fromCodePoint for better Unicode support, matching lib/keycloak.js approach
  const binString = String.fromCodePoint(...bytes);
  return btoa(binString);
};

export const sha256Digest = async (message: string): Promise<ArrayBuffer> => {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  if (!globalThis.crypto?.subtle)
    throw new Error("Web Crypto API is not available.");
  return await crypto.subtle.digest("SHA-256", data);
};

export const buildClaimsParameter = (requestedAcr: any): string =>
  JSON.stringify({ id_token: { acr: requestedAcr } });

export const createPromise = <T>() => {
  let resolve: (value: T) => void;
  let reject: (reason?: any) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return {
    promise,
    setSuccess: resolve!,
    setError: reject!,
  };
};

export const applyTimeoutToPromise = async <T>(
  promise: Promise<T>,
  timeout: number,
  errorMessage?: string,
): Promise<T> => {
  let timeoutHandle: any = null;
  const timeoutPromise = new Promise<T>((_, reject) => {
    timeoutHandle = setTimeout(() => {
      reject({
        error: errorMessage || `Promise not settled within ${timeout}ms`,
      });
    }, timeout);
  });
  return await Promise.race([promise, timeoutPromise]).finally(() =>
    clearTimeout(timeoutHandle),
  );
};

export const safeStringField = (
  obj: unknown,
  field: string,
): string | undefined => {
  if (obj && typeof obj === "object" && typeof (obj as any)[field] === "string")
    return (obj as any)[field];

  return undefined;
};

export const stripTrailingSlash = (url: string): string => {
  return url.endsWith("/") ? url.slice(0, -1) : url;
};

export const waitForTimeout = (delay: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, delay));

export const generateRandomData = (len: number): Uint8Array => {
  if (
    typeof crypto === "undefined" ||
    typeof crypto.getRandomValues === "undefined"
  ) {
    throw new Error("Web Crypto API is not available.");
  }
  return crypto.getRandomValues(new Uint8Array(len));
};

export const generateRandomString = (
  len: number,
  alphabet: string,
): string => {
  const randomData = generateRandomData(len);
  const chars = new Array(len);
  for (let i = 0; i < len; i++) {
    chars[i] = alphabet.charCodeAt(randomData[i] % alphabet.length);
  }
  return String.fromCharCode(...chars);
};
