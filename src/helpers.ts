import { getRandomValues, subtle } from "node:crypto";
import type { IKeycloakTokenParsed } from "./types.js";

export const isObject = <T>(input: unknown): input is T =>
  typeof input === "object" && input !== null;

export const decodeToken = (token: string): IKeycloakTokenParsed => {
  const [_header, payload, _signature] = token.split(".");

  if (typeof payload !== "string")
    throw new Error("Unable to decode token, payload not found.");

  try {
    const decoded = base64UrlDecode(payload);

    try {
      return JSON.parse(decoded) as IKeycloakTokenParsed;
    } catch (error: unknown) {
      throw new Error(
        "Unable to decode token, payload is not a valid JSON value.",
        { cause: error },
      );
    }
  } catch (error: unknown) {
    throw new Error(
      "Unable to decode token, payload is not a valid Base64URL value.",
      { cause: error },
    );
  }
};

const base64UrlDecode = (input: string): string => {
  const output: string[] = [input.replaceAll("-", "+").replaceAll("_", "/")];
  switch (output.length % 4) {
    case 0:
      break;
    case 2:
      output.push("==");
      break;
    case 3:
      output.push("=");
      break;
    default:
      throw new Error("Input is not of the correct length.");
  }

  const data = output.join("");
  try {
    return b64DecodeUnicode(data);
  } catch {
    return atob(data);
  }
};

const b64DecodeUnicode = (input: string): string =>
  decodeURIComponent(
    atob(input).replace(/(.)/g, (_match, suffix) => {
      const code = suffix.charCodeAt(0).toString(16).toUpperCase();
      return `%${code.length < 2 ? "0" : ""}${code}`;
    }),
  );

export const bytesToBase64 = (bytes: Uint8Array): string =>
  btoa(String.fromCodePoint(...bytes));

export const sha256Digest = async (message: string): Promise<ArrayBuffer> => {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  return await subtle.digest("SHA-256", data);
};

export const buildClaimsParameter = (requestedAcr: unknown): string =>
  JSON.stringify({ id_token: { acr: requestedAcr } });

export const createPromise = <T>() => {
  let resolve: (value: T) => void;
  let reject: (reason?: unknown) => void;
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
  let timeoutHandle: NodeJS.Timeout;

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

export const safeStringField = <T>(
  obj: unknown,
  field: keyof T,
): string | undefined => {
  if (isObject<T>(obj) && typeof obj[field] === "string") return obj[field];
  return;
};

export const stripTrailingSlash = (url: string): string =>
  url.endsWith("/") ? url.slice(0, -1) : url;

export const waitForTimeout = (delay: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, delay));

export const generateRandomData = (len: number): Uint8Array =>
  getRandomValues(new Uint8Array(len));

export const generateRandomString = (len: number, alphabet: string): string =>
  String.fromCharCode(
    ...generateRandomData(len).map((value) =>
      alphabet.charCodeAt(value % alphabet.length),
    ),
  );
