import { type Bytes, trimDer, verify } from './certificate';
import Native, { type PinStatus } from './native';

export type { PinStatus } from './native';

/** Pass instead of the PIN to use the one saved with `savePin`, unlocked with Face ID, Touch ID or a fingerprint. */
export const SAVED_PIN: unique symbol = Symbol('SAVED_PIN');

/** The full 8-digit PIN, or `SAVED_PIN`. */
export type Pin = string | typeof SAVED_PIN;

/**
 * Progress of a session, in order: `detected` the card is on the phone; `pin` the PIN is being verified; `ready` the PIN
 * is verified and the certificate read, `use` starts; `signing` a signature starts, once per `sign`; `done` `use`
 * resolved and the session is over.
 */
export type CieStep = 'detected' | 'pin' | 'ready' | 'signing' | 'done';

const STEPS: CieStep[] = ['detected', 'pin', 'ready', 'signing', 'done'];

const MESSAGES: Record<CieStep, string> = {
  detected: 'CIE rilevata, non allontanarla',
  pin: 'Verifica del PIN…',
  ready: 'PIN verificato',
  signing: 'Firma in corso…',
  done: 'Operazione completata',
};

/**
 * `prompt`, `error`: texts of the iOS NFC sheet while it waits for the card and when the session fails; `messages`: its
 * text at each step. `onStep`: called at each step, e.g. to show progress on Android, which has no NFC sheet.
 * `savePin`: once the card accepts the PIN, save it for `SAVED_PIN`. `biometricPrompt`, `biometricCancel`: texts of the
 * biometric prompt shown before the card is read, wherever the secure hardware requires one: `SAVED_PIN` everywhere,
 * `savePin` on Android only.
 */
export type CieOptions = {
  prompt?: string;
  error?: string;
  messages?: Partial<Record<CieStep, string>>;
  onStep?: (step: CieStep) => void;
  savePin?: boolean;
  biometricPrompt?: string;
  biometricCancel?: string;
};

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
    onStep,
  } = options;
  const message = (s: CieStep) => options.messages?.[s] ?? MESSAGES[s];
  const id = ++session;
  let done = false;
  // Native events can arrive after `ready`: steps only move forward, except one `signing` per signature.
  let reached = -1;
  const step = (s: CieStep) => {
    const i = STEPS.indexOf(s);
    if (i < reached || (i === reached && s !== 'signing')) return;
    reached = i;
    onStep?.(s);
  };
  const subscription = onStep && Native.addListener('onStep', (event) => event.id === id && step(event.step));
  try {
    const sheet = { prompt, detected: message('detected'), pin: message('pin'), ready: message('ready'), signing: message('signing') };
    const certificate = trimDer(await Native.connect(id, pin === SAVED_PIN ? null : pin, savePin, sheet, biometricPrompt, biometricCancel));
    step('ready');
    let last: Promise<unknown> = Promise.resolve();
    const sign = (digestInfo: Bytes) => {
      const input = digestInfo.slice(); // signed later, once the calls before it finish
      const signature = last.then(async () => {
        step('signing');
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
    subscription?.remove();
    Native.close(id, done ? null : error, done ? message('done') : null);
    if (done) step('done');
  }
}

/** Aborts the CIE session in progress. */
export const cancel = () => Native.close(session, null, null);

/** Whether a PIN is saved, without showing any UI. */
export const pinStatus = (): Promise<PinStatus> => Native.pinStatus();

/** Deletes the saved PIN. */
export const forgetPin = (): Promise<void> => Native.forgetPin();
