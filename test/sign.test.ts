import { PDFDocument, PDFName } from '@cantoo/pdf-lib';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { privateEncrypt } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { SAVED_PIN, type Signer, cancel, cieSigner, signCades, signPades } from '../src/index';
import { card } from './expo';

const dir = mkdtempSync(join(tmpdir(), 'ciesign-'));
const openssl = (...args: string[]) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'key.pem', '-out', 'cert.pem', '-days', '1', '-subj', '/C=IT/CN=ROSSI MARIO');
const certificate = new Uint8Array(openssl('x509', '-in', 'cert.pem', '-outform', 'DER'));
const key = readFileSync(join(dir, 'key.pem'));
const signer: Signer = async (toBeSigned) => new Uint8Array(privateEncrypt(key, await toBeSigned(certificate)));

const verify = (cms: Uint8Array, content: Uint8Array, name: string) => {
  writeFileSync(join(dir, `${name}.p7s`), cms);
  writeFileSync(join(dir, `${name}.bin`), content);
  openssl('cms', '-verify', '-binary', '-inform', 'DER', '-in', `${name}.p7s`, '-content', `${name}.bin`, '-CAfile', 'cert.pem', '-purpose', 'any', '-out', '/dev/null');
};

const signatures = (pdf: Uint8Array) =>
  [...Buffer.from(pdf).toString('latin1').matchAll(/\/ByteRange \[0 (\d+) (\d+) (\d+)\s*\]/g)].map((m) => {
    const [a, b, c] = m.slice(1).map(Number);
    return {
      length: b + c,
      content: Buffer.concat([pdf.subarray(0, a), pdf.subarray(b, b + c)]),
      cms: Buffer.from(Buffer.from(pdf.subarray(a + 1, b - 1)).toString('latin1').replace(/(00)+$/, ''), 'hex'),
    };
  });

for (const useObjectStreams of [false, true]) {
  test(`PAdES, two signatures, ${useObjectStreams ? 'xref stream' : 'xref table'}`, async () => {
    const doc = await PDFDocument.create();
    doc.addPage().drawText('Verbale di assemblea');
    const pdf = await doc.save({ useObjectStreams });
    const once = await signPades(pdf, signer, { reason: 'Approvazione', location: 'Forlì' });
    const twice = await signPades(once, signer);
    assert.deepEqual(twice.subarray(0, once.length), once);
    const found = signatures(twice);
    assert.deepEqual(found.map((s) => s.length), [once.length, twice.length]);
    found.forEach(({ cms, content }, i) => verify(cms, content, `pades-${useObjectStreams}-${i}`));
    writeFileSync(join(dir, `signed-${useObjectStreams}.pdf`), twice);
    const reloaded = await PDFDocument.load(twice);
    assert.deepEqual(reloaded.getForm().getFields().map((f) => f.getName()), ['Signature1', 'Signature2']);
    const contents = (d: PDFDocument) => String(d.getPage(0).node.get(PDFName.of('Contents')));
    assert.equal(contents(reloaded), contents(await PDFDocument.load(pdf)));
  });
}

test('CAdES enveloping .p7m', async () => {
  const content = new TextEncoder().encode('documento da firmare\n');
  const p7m = await signCades(content, signer);
  writeFileSync(join(dir, 'doc.p7m'), p7m);
  const out = openssl('cms', '-verify', '-binary', '-inform', 'DER', '-in', 'doc.p7m', '-CAfile', 'cert.pem', '-purpose', 'any');
  assert.deepEqual(new Uint8Array(out), content);
});

const content = new TextEncoder().encode('documento da firmare\n');
const padded = new Uint8Array(certificate.length + 64); // EF 1003 is zero-filled after the certificate
padded.set(certificate);
const fakeCard = (tamper = (signature: Uint8Array) => signature) => {
  card.closed = [];
  card.connect = async () => padded;
  card.sign = async (_id, digestInfo) => tamper(new Uint8Array(privateEncrypt(key, digestInfo)));
};

test('CIE signer: one session, padded certificate, closed on success', async () => {
  fakeCard();
  const p7m = await signCades(content, cieSigner('12345678'));
  writeFileSync(join(dir, 'cie.p7m'), p7m);
  openssl('cms', '-verify', '-binary', '-inform', 'DER', '-in', 'cie.p7m', '-CAfile', 'cert.pem', '-purpose', 'any', '-out', '/dev/null');
  assert.equal(card.closed.length, 1);
  assert.equal(card.closed[0][1], null);
});

test('CIE signer rejects signatures that do not match the certificate', async () => {
  fakeCard((signature) => (signature[0] ^= 1, signature));
  await assert.rejects(signCades(content, cieSigner('12345678', { error: 'Errore' })), { code: 'CARD_ERROR' });
  assert.equal(card.closed[0][1], 'Errore');
  fakeCard(() => new Uint8Array());
  await assert.rejects(signCades(content, cieSigner('12345678')), { code: 'CARD_ERROR' });
});

test('cancel() stops signers created before it, also while the document is prepared', async () => {
  fakeCard();
  const signer = cieSigner('12345678');
  cancel();
  await assert.rejects(signCades(content, signer), { code: 'CANCELLED' });
  await signCades(content, cieSigner('12345678'));
});

test('the PIN is checked before the card is touched', async () => {
  fakeCard();
  await assert.rejects(signCades(content, cieSigner('1234')), /8 digits/);
  assert.equal(card.closed.length, 0);
});

test('SAVED_PIN leaves the PIN to the native side; savePin is passed through', async () => {
  fakeCard();
  const calls: [string | null, boolean][] = [];
  card.connect = async (_id, pin, save) => (calls.push([pin, save]), padded);
  await signCades(content, cieSigner(SAVED_PIN));
  await signCades(content, cieSigner('12345678', { savePin: true }));
  await signCades(content, cieSigner('12345678'));
  assert.deepEqual(calls, [[null, false], ['12345678', true], ['12345678', false]]);
});

test.after(() => console.log(`output: ${dir}`));
