import { type Bytes, type Signer, fail, sha256, signedData, trimDer, verify } from './cms';
import Native from './native';

export type { Signer } from './cms';
export { signPades, type PadesOptions } from './pades';

/** Texts of the iOS NFC sheet. */
export type CieOptions = { prompt?: string; error?: string };

/** Enveloping CAdES-BES signature: the DER content of a .p7m file. */
export const signCades = async (content: Bytes, signer: Signer): Promise<Bytes> =>
  signedData(await sha256(content), signer, content);

let epoch = 0; // bumped by cancel()
let session = 0; // id of the latest NFC session

async function withCard<T>(created: number, pin: string, options: CieOptions, use: (certificate: Bytes, id: number) => Promise<T>) {
  if (!/^\d{8}$/.test(pin)) throw new Error('The CIE PIN has 8 digits');
  if (created !== epoch) throw fail('CANCELLED', 'Cancelled');
  const { prompt = "Avvicina la CIE al retro dell'iPhone", error = 'Operazione non riuscita' } = options;
  const id = ++session;
  let done = false;
  try {
    const result = await use(trimDer(await Native.connect(id, pin, prompt)), id);
    done = true;
    return result;
  } finally {
    Native.close(id, done ? null : error);
  }
}

/** Signs with the CIE in a single NFC tap; `pin` is the full 8-digit PIN. */
export const cieSigner = (pin: string, options: CieOptions = {}): Signer => {
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
export const readCertificate = (pin: string, options: CieOptions = {}): Promise<Bytes> =>
  withCard(epoch, pin, options, async (certificate) => certificate);

/** Aborts the CIE operation in progress and invalidates every signer created before this call. */
export const cancel = () => {
  epoch++;
  Native.close(session, null);
};
