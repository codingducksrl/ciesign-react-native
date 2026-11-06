export type Bytes = Uint8Array;

export const fail = (code: string, message: string) => Object.assign(new Error(message), { code });

const hex = (bytes: Bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** Value start and end offsets of the DER TLV at `i`. */
const bounds = (der: Bytes, i = 0) => {
  let length = der[i + 1];
  let start = i + 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    length = 0;
    for (let k = 0; k < n; k++) length = length * 256 + der[start++];
  }
  return { start, end: start + length };
};

/** The TLVs inside a constructed DER value. */
const children = (der: Bytes): Bytes[] => {
  const out: Bytes[] = [];
  for (let i = bounds(der).start; i < bounds(der).end; i = bounds(der, i).end) out.push(der.subarray(i, bounds(der, i).end));
  return out;
};

const value = (der: Bytes) => der.subarray(bounds(der).start, bounds(der).end);

/** Drops the padding after the certificate (the CIE stores it in a zero-filled file). */
export const trimDer = (der: Bytes) => {
  const { end } = bounds(der);
  if (der[0] !== 0x30 || !(end <= der.length)) throw fail('CARD_ERROR', 'Invalid certificate');
  return der.subarray(0, end);
};

/** Checks an RSA PKCS#1 v1.5 signature of `digestInfo` against the certificate's public key. */
export const verify = (certificate: Bytes, digestInfo: Bytes, signature: Bytes) => {
  const fields = children(children(certificate)[0]); // TBSCertificate, with or without [0] version
  const spki = children(fields[fields[0][0] === 0xa0 ? 6 : 5]);
  const [n, e] = children(value(spki[1]).subarray(1)).map((i) => BigInt('0x' + hex(value(i))));
  let result = 1n;
  for (let base = BigInt('0x' + (hex(signature) || '0')) % n, x = e; x > 0n; x >>= 1n, base = (base * base) % n) {
    if (x & 1n) result = (result * base) % n;
  }
  const k = (n.toString(16).length + 1) >> 1;
  const encoded = '01' + 'ff'.repeat(k - digestInfo.length - 3) + '00' + hex(digestInfo);
  if (signature.length !== k || result !== BigInt('0x' + encoded)) throw fail('CARD_ERROR', 'The signature does not match the certificate');
};
