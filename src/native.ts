import { requireNativeModule } from 'expo';

/** `saved`: a PIN is saved. `available`: a strong biometric is enrolled, so one can be. `unavailable`: neither. */
export type PinStatus = 'saved' | 'available' | 'unavailable';

/** Steps only the native side sees: the card was detected; the PIN is being verified. */
export type NativeStep = 'detected' | 'pin';

/** iOS NFC sheet texts: `prompt` while waiting for the card, then one per step. */
export type NativeMessages = { prompt: string; detected: string; pin: string; ready: string; signing: string };

type CieSignModule = {
  /**
   * Shows the biometric prompt and unlocks the saved PIN for session `id`, which `connect` with a null `pin` then sends to
   * the card. Returns the certificate saved with the PIN when `useSavedCertificate` and it is of the same card: that
   * session's `connect` returns it instead of reading it. Null otherwise.
   */
  unlock(id: number, biometricPrompt: string, biometricCancel: string, useSavedCertificate: boolean): Promise<Uint8Array | null>;
  /**
   * Waits for the card, verifies the PIN and returns its certificate; NFC session `id` stays open.
   * A null `pin` is the one `unlock` unlocked for `id`; `save` saves `pin` once the card accepts it, after the biometric
   * prompt where the secure hardware requires one (Android).
   */
  connect(id: number, pin: string | null, save: boolean, messages: NativeMessages, biometricPrompt: string, biometricCancel: string): Promise<Uint8Array>;
  /** Signs a DigestInfo in session `id`, as many times as needed until it closes. */
  sign(id: number, digestInfo: Uint8Array): Promise<Uint8Array>;
  /**
   * Ends every session up to `id`, also one whose connect has not arrived yet. iOS shows `error` in the NFC sheet, or
   * else `done` next to its checkmark.
   */
  close(id: number, error: string | null, done: string | null): void;
  pinStatus(): Promise<PinStatus>;
  forgetPin(): Promise<void>;
  /** The certificate file saved with the PIN, without any UI; null when none is saved. */
  savedCertificate(): Promise<Uint8Array | null>;
  /** `onStep` fires as session `id` reaches a step only the native side sees. */
  addListener(event: 'onStep', listener: (event: { id: number; step: NativeStep }) => void): { remove(): void };
};

export default requireNativeModule<CieSignModule>('CieSign');
