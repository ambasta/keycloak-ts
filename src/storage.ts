import type { ICallbackState, ICallbackStorage } from "./types.ts";
import { isObject } from "./helpers.ts"; // For #parseExpiry

const STORAGE_KEY_PREFIX = "kc-callback-";

export class LocalStorageStore implements ICallbackStorage {
  constructor() {
    // Check for localStorage availability
    try {
      localStorage.setItem("kc-test", "test");
      localStorage.removeItem("kc-test");
    } catch (e) {
      throw new Error("localStorage is not available in this environment.");
    }
  }

  public get(state: string): ICallbackState | undefined {
    if (!state) {
      return undefined;
    }

    const key = STORAGE_KEY_PREFIX + state;
    const value = localStorage.getItem(key);

    if (value) {
      localStorage.removeItem(key);
      try {
        const parsedValue = JSON.parse(value) as ICallbackState;
        // expires property is part of the stored wrapper object, not ICallbackState itself directly.
        // The ICallbackState from storage should not have 'expires' in its direct type.
        // We expect the stored object to be { ...ICallbackState, expires: number }
        // So, we return the state part.
        // If ICallbackState itself had an optional 'expires' (e.g. for other uses),
        // it would be fine, but here it's a storage-internal field.
        const { expires, ...stateData } = parsedValue as ICallbackState & { expires?: number };
        this.#clearInvalidValues();
        return stateData;
      } catch (e) {
        // If parsing fails, it's not a valid stored state.
        this.#clearInvalidValues(); // Still attempt cleanup
        return undefined;
      }
    }

    this.#clearInvalidValues();
    return undefined;
  }

  public add(state: ICallbackState): void {
    this.#clearInvalidValues();

    const key = STORAGE_KEY_PREFIX + state.state;
    // Store the state along with an expiry time (1 hour from now)
    const value = JSON.stringify({
      ...state,
      expires: Date.now() + 60 * 60 * 1000,
    });

    try {
      localStorage.setItem(key, value);
    } catch (error) {
      // If storage is full, clear all known Keycloak callback values and try again.
      console.warn(
        "[KEYCLOAK] Failed to store callback state in localStorage, clearing old states and retrying.",
        error,
      );
      this.#clearAllValues();
      try {
        localStorage.setItem(key, value);
      } catch (finalError) {
        // If it still fails, log an error. The callback state will be lost.
        console.error(
          "[KEYCLOAK] Failed to store callback state in localStorage even after clearing known entries.",
          finalError,
        );
      }
    }
  }

  /**
   * Gets all entries stored in local storage that are known to be managed by this class.
   * @returns {Array<[string, unknown]>} An array of key-value pairs.
   */
  #getStoredEntries(): Array<[string, string]> {
    return Object.entries(localStorage).filter(([key]) =>
      key.startsWith(STORAGE_KEY_PREFIX),
    ) as Array<[string, string]>; // Ensure value is string
  }

  /**
   * Parses the expiry time from a value stored in local storage.
   * @param {unknown} value
   * @returns {number | null} The expiry time in milliseconds, or `null` if the value is malformed.
   */
  #parseExpiry(value: string): number | null {
    let parsedValue;

    // Attempt to parse the value as JSON.
    try {
      parsedValue = JSON.parse(value);
    } catch (error) {
      return null;
    }

    // Attempt to extract the 'expires' property.
    if (
      isObject(parsedValue) &&
      "expires" in parsedValue &&
      typeof parsedValue.expires === "number"
    ) {
      return parsedValue.expires;
    }

    return null;
  }

  /**
   * Clears all values from local storage that are no longer valid.
   */
  #clearInvalidValues(): void {
    const currentTime = Date.now();
    for (const [key, value] of this.#getStoredEntries()) {
      const expiry = this.#parseExpiry(value);
      if (expiry === null || expiry < currentTime) {
        localStorage.removeItem(key);
      }
    }
  }

  /**
   * Clears all known values from local storage.
   */
  #clearAllValues(): void {
    for (const [key] of this.#getStoredEntries()) {
      localStorage.removeItem(key);
    }
  }
}

export class CookieStorageStore implements ICallbackStorage {
  private static readonly STORAGE_KEY_PREFIX = "kc-callback-"; // Redefine or ensure accessible if moved

  public get(state: string): ICallbackState | undefined {
    if (!state) {
      return undefined;
    }

    const key = CookieStorageStore.STORAGE_KEY_PREFIX + state;
    const value = this.#getCookie(key);

    // Clear the cookie once retrieved
    this.#setCookie(key, "", this.#cookieExpiration(-100));

    if (value) {
      try {
        return JSON.parse(value) as ICallbackState;
      } catch (e) {
        // If parsing fails, treat as if not found
        return undefined;
      }
    }
    return undefined;
  }

  public add(state: ICallbackState): void {
    const key = CookieStorageStore.STORAGE_KEY_PREFIX + state.state;
    const value = JSON.stringify(state);
    // Cookie expires in 60 minutes, matching lib/keycloak.js
    this.#setCookie(key, value, this.#cookieExpiration(60));
  }

  // This method is part of ICallbackStorage but not strictly used by CookieStorageStore internally
  // for lib/keycloak.js's get/add logic (get already removes).
  // However, providing it for completeness if an external clear is needed.
  public removeItem(key: string): void {
    this.#setCookie(key, "", this.#cookieExpiration(-100));
  }

  #cookieExpiration(minutes: number): Date {
    const exp = new Date();
    exp.setTime(exp.getTime() + minutes * 60 * 1000);
    return exp;
  }

  #getCookie(key: string): string {
    const name = key + "=";
    const ca = document.cookie.split(";");
    for (let i = 0; i < ca.length; i++) {
      let c = ca[i];
      while (c.charAt(0) === " ") {
        c = c.substring(1);
      }
      if (c.indexOf(name) === 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
  }

  #setCookie(key: string, value: string, expirationDate: Date): void {
    // Ensure cookies are set with SameSite=Lax and Secure if appropriate
    // For now, matching basic behavior of lib/keycloak.js
    // Path=/ might be needed for wider accessibility if redirects occur across paths
    let cookieString =
      key +
      "=" +
      value +
      "; " +
      "expires=" +
      expirationDate.toUTCString() +
      "; path=/";
    
    // Add Secure and SameSite=Lax attributes if in a secure context
    if (globalThis.isSecureContext) {
      cookieString += "; Secure; SameSite=Lax";
    }
    document.cookie = cookieString;
  }
}

export const createCallbackStorage = (): ICallbackStorage => {
  try {
    // Attempt to use LocalStorageStore first
    return new LocalStorageStore();
  } catch (e) {
    // Fallback to CookieStorageStore if LocalStorage is not available
    return new CookieStorageStore();
  }
};
