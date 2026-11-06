import Native from './native';

export type Bytes = Uint8Array;

/**
 * Produces an RSA PKCS#1 v1.5 signature: it must call `toBeSigned` with the signer's DER
 * certificate and sign the DigestInfo it resolves to.
 */
export type Signer = (toBeSigned: (certificate: Bytes) => Promise<Bytes>) => Promise<Bytes>;

const OID = {
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha256WithRSA: '1.2.840.113549.1.1.11',
};

export const sha256 = (data: Bytes): Promise<Bytes> => Native.sha256(data);

export const hex = (bytes: Bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export const concat = (...parts: Bytes[]): Bytes => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
};

const lengthOf = (n: number): number[] => {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (; n > 0; n = Math.floor(n / 256)) bytes.unshift(n % 256);
  return [0x80 | bytes.length, ...bytes];
};

const tlv = (tag: number, ...parts: Bytes[]): Bytes => {
  const body = concat(...parts);
  return concat(Uint8Array.of(tag, ...lengthOf(body.length)), body);
};

// X.690 SET OF order: encodings compared as octet strings, the shorter padded with zeros.
const derOrder = (a: Bytes, b: Bytes) => {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d) return d;
  }
  return 0;
};

const seq = (...parts: Bytes[]) => tlv(0x30, ...parts);
const set = (...parts: Bytes[]) => tlv(0x31, ...parts.sort(derOrder));
const tagged = (n: number, ...parts: Bytes[]) => tlv(0xa0 | n, ...parts);
const octets = (b: Bytes) => tlv(0x04, b);
const one = Uint8Array.of(0x02, 0x01, 0x01);
const nul = Uint8Array.of(0x05, 0x00);
const utcTime = (d: Date) =>
  tlv(0x17, Uint8Array.from(d.toISOString().replace(/\D/g, '').slice(2, 14) + 'Z', (c) => c.charCodeAt(0)));
const oid = (dotted: string) => {
  const [a, b, ...arcs] = dotted.split('.').map(Number);
  const out = [40 * a + b];
  for (let v of arcs) {
    const arc = [v & 0x7f];
    while ((v >>>= 7)) arc.unshift(0x80 | (v & 0x7f));
    out.push(...arc);
  }
  return tlv(0x06, Uint8Array.from(out));
};
const attribute = (type: string, value: Bytes) => seq(oid(type), set(value));

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

/** TBSCertificate fields from serialNumber on: serial, signature, issuer, validity, subject, subjectPublicKeyInfo. */
const tbs = (certificate: Bytes) => {
  const fields = children(children(certificate)[0]);
  return fields[0][0] === 0xa0 ? fields.slice(1) : fields;
};

export const fail = (code: string, message: string) => Object.assign(new Error(message), { code });

/** Drops the padding after the certificate (the CIE stores it in a zero-filled file). */
export const trimDer = (der: Bytes) => {
  const { end } = bounds(der);
  if (der[0] !== 0x30 || !(end <= der.length)) throw fail('CARD_ERROR', 'Invalid certificate');
  return der.subarray(0, end);
};

/** Checks an RSA PKCS#1 v1.5 signature of `digestInfo` against the certificate's public key. */
export const verify = (certificate: Bytes, digestInfo: Bytes, signature: Bytes) => {
  const spki = children(tbs(certificate)[5]);
  const [n, e] = children(value(spki[1]).subarray(1)).map((i) => BigInt('0x' + hex(value(i))));
  let result = 1n;
  for (let base = BigInt('0x' + (hex(signature) || '0')) % n, x = e; x > 0n; x >>= 1n, base = (base * base) % n) {
    if (x & 1n) result = (result * base) % n;
  }
  const k = (n.toString(16).length + 1) >> 1;
  const encoded = '01' + 'ff'.repeat(k - digestInfo.length - 3) + '00' + hex(digestInfo);
  if (signature.length !== k || result !== BigInt('0x' + encoded)) throw fail('CARD_ERROR', 'The signature does not match the certificate');
};

/**
 * CMS SignedData (CAdES-BES) over `digest`, the SHA-256 of the signed content.
 * With `content` the signature is enveloped and carries signing-time (.p7m); without it, it is
 * detached and has no signing-time, as PAdES baseline requires.
 */
export async function signedData(digest: Bytes, signer: Signer, content?: Bytes): Promise<Bytes> {
  let certificate!: Bytes;
  let attributes!: Bytes;
  const signature = await signer(async (cert) => {
    certificate = cert;
    const [serial, , issuer] = tbs(certificate);
    attributes = set(
      attribute(OID.contentType, oid(OID.data)),
      ...(content ? [attribute(OID.signingTime, utcTime(new Date()))] : []),
      attribute(OID.messageDigest, octets(digest)),
      // ESSCertIDv2 omits hashAlgorithm because SHA-256 is its DEFAULT.
      attribute(OID.signingCertificateV2, seq(seq(seq(octets(await sha256(certificate)), seq(seq(tagged(4, issuer)), serial))))),
    );
    return seq(seq(oid(OID.sha256), nul), octets(await sha256(attributes)));
  });

  const [serial, , issuer] = tbs(certificate);
  const signedAttrs = Uint8Array.from(attributes);
  signedAttrs[0] = 0xa0; // [0] IMPLICIT; the signature covers the SET encoding
  const signerInfo = seq(one, seq(issuer, serial), seq(oid(OID.sha256)), signedAttrs, seq(oid(OID.sha256WithRSA), nul), octets(signature));
  const encapsulated = seq(oid(OID.data), ...(content ? [tagged(0, octets(content))] : []));
  return seq(oid(OID.signedData), tagged(0, seq(one, set(seq(oid(OID.sha256))), encapsulated, tagged(0, certificate), set(signerInfo))));
}
