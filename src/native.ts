import { requireNativeModule } from 'expo';

/** `saved`: a PIN is saved. `available`: a strong biometric is enrolled, so one can be. `unavailable`: neither. */
export type PinStatus = 'saved' | 'available' | 'unavailable';

type CieSignModule = {
  /**
   * Waits for the card, verifies the PIN and returns its certificate; NFC session `id` stays open.
   * A null `pin` unlocks the saved one; `save` saves `pin` once the card accepts it. Each shows the biometric prompt first
   * only where the secure hardware requires it: unlocking everywhere, saving on Android.
   */
  connect(id: number, pin: string | null, save: boolean, prompt: string, biometricPrompt: string, biometricCancel: string): Promise<Uint8Array>;
  /** Signs a DigestInfo in session `id`, as many times as needed until it closes. */
  sign(id: number, digestInfo: Uint8Array): Promise<Uint8Array>;
  /** Ends every session up to `id`, also one whose connect has not arrived yet; iOS shows `error` in the NFC sheet. */
  close(id: number, error: string | null): void;
  pinStatus(): Promise<PinStatus>;
  forgetPin(): Promise<void>;
};

export default requireNativeModule<CieSignModule>('CieSign');
