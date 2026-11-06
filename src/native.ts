import { requireNativeModule } from 'expo';

type CieSignModule = {
  sha256(data: Uint8Array): Promise<Uint8Array>;
  /** Waits for the card, verifies the PIN and returns its certificate; NFC session `id` stays open. */
  connect(id: number, pin: string, prompt: string): Promise<Uint8Array>;
  /** Signs a DigestInfo in session `id`. */
  sign(id: number, digestInfo: Uint8Array): Promise<Uint8Array>;
  /** Ends every session up to `id`, also one whose connect has not arrived yet; iOS shows `error` in the NFC sheet. */
  close(id: number, error: string | null): void;
};

export default requireNativeModule<CieSignModule>('CieSign');
