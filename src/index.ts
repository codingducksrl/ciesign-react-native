import { type Bytes, type Signer, fail, sha256, signedData, trimDer, verify } from './cms';
import Native, { type PinStatus } from './native';

export type { Signer } from './cms';
export type { PinStatus } from './native';
export { signPades, type PadesOptions } from './pades';

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

/** Enveloping CAdES-BES signature: the DER content of a .p7m file. */
export const signCades = async (content: Bytes, signer: Signer): Promise<Bytes> =>
  signedData(await sha256(content), signer, content);

let epoch = 0; // bumped by cancel()
let session = 0; // id of the latest NFC session

async function withCard<T>(created: number, pin: Pin, options: CieOptions, use: (certificate: Bytes, id: number) => Promise<T>) {
  if (pin !== SAVED_PIN && !/^\d{8}$/.test(pin)) throw new Error('The CIE PIN has 8 digits');
  if (created !== epoch) throw fail('CANCELLED', 'Cancelled');
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
    const certificate = await Native.connect(id, pin === SAVED_PIN ? null : pin, savePin, prompt, biometricPrompt, biometricCancel);
    const result = await use(trimDer(certificate), id);
    done = true;
    return result;
  } finally {
    Native.close(id, done ? null : error);
  }
}

/** Signs with the CIE in a single NFC tap. */
export const cieSigner = (pin: Pin, options: CieOptions = {}): Signer => {
  const created = epoch;
  return (toBeSigned) =>
    withCard(created, pin, options, async (certificate, id) => {
      const digestInfo = await toBeSigned(certificate);
      const signature = await Native.sign(id, digestInfo);
      verify(certificate, digestInfo, signature);
      return signature;
    });
};

/** Reads the CIE authentication certificate (DER). */
export const readCertificate = (pin: Pin, options: CieOptions = {}): Promise<Bytes> =>
  withCard(epoch, pin, options, async (certificate) => certificate);

/** Aborts the CIE operation in progress and invalidates every signer created before this call. */
export const cancel = () => {
  epoch++;
  Native.close(session, null);
};

/** Whether a PIN is saved, without showing any UI. */
export const pinStatus = (): Promise<PinStatus> => Native.pinStatus();

/** Deletes the saved PIN. */
export const forgetPin = (): Promise<void> => Native.forgetPin();
