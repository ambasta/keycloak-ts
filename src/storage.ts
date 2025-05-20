import type { ICallbackState, ICallbackStorage, IExpires } from "./types.ts";
import { isObject } from "./helpers.ts";

const STORAGE_KEY_PREFIX = "kc-callback-";

export class LocalStorageStore implements ICallbackStorage {
  constructor() {
    try {
      localStorage.setItem("kc-test", "test");
      localStorage.removeItem("kc-test");
    } catch (e) {
      throw new Error("localStorage is not available in this environment.");
    }
  }

  get = (state: string): ICallbackState | undefined => {
    if (!state) return;

    const key = `${STORAGE_KEY_PREFIX}${state}`;
    const value = localStorage.getItem(key);

    if (value) {
      localStorage.removeItem(key);
      try {
        const parsedValue = JSON.parse(value) as ICallbackState;
        const { expires, ...stateData } = parsedValue as ICallbackState &
          IExpires;
        this.#clearInvalidValues();
        return stateData;
      } catch {
        this.#clearInvalidValues();
        return;
      }
    }

    this.#clearInvalidValues();
    return;
  };

  add = (state: ICallbackState): void => {
    this.#clearInvalidValues();

    const key = `${STORAGE_KEY_PREFIX}${state.state}`;
    const value = JSON.stringify({
      ...state,
      expires: Date.now() + 60 * 60 * 1000,
    });

    try {
      localStorage.setItem(key, value);
    } catch (error) {
      console.warn(
        "[KEYCLOAK] Failed to store callback state in localStorage, clearing old states and retrying.",
        error,
      );
      this.#clearAllValues();
      try {
        localStorage.setItem(key, value);
      } catch (finalError) {
        console.error(
          "[KEYCLOAK] Failed to store callback state in localStorage even after clearing known entries.",
          finalError,
        );
      }
    }
  };

  #getStoredEntries = (): Array<[string, string]> =>
    Object.entries(localStorage).filter(([key]) =>
      key.startsWith(STORAGE_KEY_PREFIX),
    );

  #parseExpiry = (value: string): number | undefined => {
    try {
      const parsedValue = JSON.parse(value);
      if (
        isObject<IExpires>(parsedValue) &&
        "expires" in parsedValue &&
        typeof parsedValue.expires === "number"
      )
        return parsedValue.expires;
    } catch {
      return;
    }
    return;
  };

  #clearInvalidValues = (): void => {
    const currentTime = Date.now();

    this.#getStoredEntries().forEach(([key, value]) => {
      const expiry = this.#parseExpiry(value);
      if (expiry === undefined || expiry < currentTime)
        localStorage.removeItem(key);
    });
  };

  #clearAllValues = (): void => {
    this.#getStoredEntries().forEach(([key]) => {
      localStorage.removeItem(key);
    });
  };
}

export class CookieStorageStore implements ICallbackStorage {
  static readonly #STORAGE_KEY_PREFIX = "kc-callback-";

  get = (state: string): ICallbackState | undefined => {
    if (!state) return;

    const key = `${CookieStorageStore.#STORAGE_KEY_PREFIX}${state}`;
    const value = this.#getCookie(key);

    this.#setCookie(key, "", this.#cookieExpiration(-100));

    if (value)
      try {
        return JSON.parse(value) as ICallbackState;
      } catch {}
    return;
  };

  add = (state: ICallbackState): void => {
    const key = `${CookieStorageStore.#STORAGE_KEY_PREFIX}${state.state}`;
    const value = JSON.stringify(state);
    this.#setCookie(key, value, this.#cookieExpiration(60));
  };

  removeItem = (key: string): void =>
    this.#setCookie(key, "", this.#cookieExpiration(-100));

  #cookieExpiration = (minutes: number): Date => {
    const exp = new Date();
    exp.setTime(exp.getTime() + minutes * 60 * 1000);
    return exp;
  };

  #getCookie = (key: string): string => {
    const name = `${key}=`;
    const parts = document.cookie.split(";");

    for (let i = 0; i < parts.length; i++) {
      let c = parts[i];
      while (c.charAt(0) === " ") {
        c = c.substring(1);
      }
      if (c.indexOf(name) === 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
  };

  #setCookie = (key: string, value: string, expirationDate: Date): void => {
    document.cookie = `${key}=${value}; expires=${expirationDate.toUTCString()}; path=/${globalThis.isSecureContext ? "; Secure; SameSite=Lax" : ""}`;
  };
}

export const createCallbackStorage = (): ICallbackStorage => {
  try {
    return new LocalStorageStore();
  } catch (e) {
    return new CookieStorageStore();
  }
};
