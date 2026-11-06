import { type Bytes, trimDer, verify } from './certificate';
import Native, { type PinStatus } from './native';

export type { PinStatus } from './native';

/** Pass instead of the PIN to use the one saved with `savePin`, unlocked with Face ID, Touch ID or a fingerprint. */
export const SAVED_PIN: unique symbol = Symbol('SAVED_PIN');

/** The full 8-digit PIN, or `SAVED_PIN`. */
export type Pin = string | typeof SAVED_PIN;

/**
 * `prompt`, `error`: texts of the iOS NFC sheet. `savePin`: once the card accepts the PIN, save it for `SAVED_PIN`.
 * `biometricPrompt`, `biometricCancel`: texts of the biometric prompt shown before the card is read, wherever the secure
 * hardware requires one: `SAVED_PIN` everywhere, `savePin` on Android only.
 */
export type CieOptions = { prompt?: string; error?: string; savePin?: boolean; biometricPrompt?: string; biometricCancel?: string };

/** A card whose PIN has been verified, for as long as `use` runs. */
export type CieSession = {
  /** DER authentication certificate; its subject holds the holder's name and fiscal code. */
  certificate: Bytes;
  /** RSA PKCS#1 v1.5 signature of a DER DigestInfo, checked against `certificate`. Calls run one at a time. */
  sign(digestInfo: Bytes): Promise<Bytes>;
};

let session = 0; // id of the latest NFC session

/**
 * Waits for the card and verifies the PIN, then runs `use`: every `sign` goes through this NFC session, which ends when
 * `use` settles.
 */
export async function cieSession<T>(pin: Pin, use: (session: CieSession) => Promise<T>, options: CieOptions = {}): Promise<T> {
  if (pin !== SAVED_PIN && !/^\d{8}$/.test(pin)) throw new Error('The CIE PIN has 8 digits');
  const {
    prompt = "Avvicina la CIE al retro dell'iPhone",
    error = 'Operazione non riuscita',
    savePin = false,
    biometricPrompt = pin === SAVED_PIN ? 'Sblocca il PIN della CIE' : 'Salva il PIN della CIE',
    biometricCancel = 'Annulla',
  } = options;
  const id = ++session;
  let done = false;
  try {
    const certificate = trimDer(await Native.connect(id, pin === SAVED_PIN ? null : pin, savePin, prompt, biometricPrompt, biometricCancel));
    let last: Promise<unknown> = Promise.resolve();
    const sign = (digestInfo: Bytes) => {
      const input = digestInfo.slice(); // signed later, once the calls before it finish
      const signature = last.then(async () => {
        const signature = await Native.sign(id, input);
        verify(certificate, input, signature);
        return signature;
      });
      last = signature.catch(() => {});
      return signature;
    };
    const result = await use({ certificate, sign });
    done = true;
    return result;
  } finally {
    Native.close(id, done ? null : error);
  }
}

/** Aborts the CIE session in progress. */
export const cancel = () => Native.close(session, null);

/** Whether a PIN is saved, without showing any UI. */
export const pinStatus = (): Promise<PinStatus> => Native.pinStatus();

/** Deletes the saved PIN. */
export const forgetPin = (): Promise<void> => Native.forgetPin();
