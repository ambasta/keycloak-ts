import {
  bytesToBase64,
  generateRandomString,
  sha256Digest,
} from "./helpers.js";

export const generateCodeVerifier = (len: number): string =>
  generateRandomString(
    len,
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  );

export const generatePkceChallenge = async (
  codeVerifier: string,
): Promise<string> =>
  bytesToBase64(new Uint8Array(await sha256Digest(codeVerifier)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
