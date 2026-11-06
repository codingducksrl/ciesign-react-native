import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { X509Certificate, createHash, privateEncrypt, verify } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { SAVED_PIN, cieSession } from '../src/index';
import { card } from './expo';

const dir = mkdtempSync(join(tmpdir(), 'ciesign-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'key.pem', '-out', 'cert.pem', '-days', '1', '-subj', '/C=IT/CN=ROSSI MARIO'], { cwd: dir, stdio: 'ignore' });
const key = readFileSync(join(dir, 'key.pem'));
const x509 = new X509Certificate(readFileSync(join(dir, 'cert.pem')));
rmSync(dir, { recursive: true });

const certificate = new Uint8Array(x509.raw);
const padded = new Uint8Array(certificate.length + 64); // EF 1003 is zero-filled after the certificate
padded.set(certificate);

const SHA256 = Buffer.from('3031300d060960864801650304020105000420', 'hex');
const digestInfo = (data: string) => new Uint8Array(Buffer.concat([SHA256, createHash('sha256').update(data).digest()]));

let connects = 0;
const fakeCard = (tamper = (signature: Uint8Array) => signature) => {
  connects = 0;
  card.closed = [];
  card.connect = async () => (connects++, padded);
  card.sign = async (_id, input) => tamper(new Uint8Array(privateEncrypt(key, input)));
};

test('one tap, several signatures, one at a time', async () => {
  fakeCard();
  let busy = false;
  const sign = card.sign;
  card.sign = async (id, input) => {
    assert.equal(busy, false);
    busy = true;
    await new Promise((resolve) => setTimeout(resolve, 5));
    busy = false;
    return sign(id, input);
  };
  const documents = ['verbale', 'allegato A', 'allegato B'];
  const signatures = await cieSession('12345678', async (cie) => {
    assert.deepEqual(cie.certificate, certificate);
    return Promise.all(documents.map((d) => cie.sign(digestInfo(d))));
  });
  documents.forEach((d, i) => assert.ok(verify('sha256', Buffer.from(d), x509.publicKey, signatures[i])));
  assert.equal(connects, 1);
  assert.deepEqual(card.closed.map(([, error]) => error), [null]);
});

test('the DigestInfo is copied when sign is called', async () => {
  fakeCard();
  await cieSession('12345678', async ({ sign }) => {
    const input = digestInfo('verbale');
    const signed = Promise.all([sign(digestInfo('allegato')), sign(input)]);
    input.fill(0);
    const [, signature] = await signed;
    assert.ok(verify('sha256', Buffer.from('verbale'), x509.publicKey, signature));
  });
});

test('signatures that do not match the certificate are rejected', async () => {
  fakeCard((signature) => (signature[0] ^= 1, signature));
  await assert.rejects(cieSession('12345678', ({ sign }) => sign(digestInfo('verbale')), { error: 'Errore' }), { code: 'CARD_ERROR' });
  assert.deepEqual(card.closed.map(([, error]) => error), ['Errore']);
  fakeCard(() => new Uint8Array());
  await assert.rejects(cieSession('12345678', ({ sign }) => sign(digestInfo('verbale'))), { code: 'CARD_ERROR' });
});

test('a failed signature does not stop the next ones', async () => {
  let calls = 0;
  fakeCard((signature) => (calls++ === 0 ? new Uint8Array() : signature));
  await cieSession('12345678', async ({ sign }) => {
    const [first, second] = await Promise.allSettled([sign(digestInfo('verbale')), sign(digestInfo('allegato'))]);
    assert.equal(first.status, 'rejected');
    assert.equal(second.status, 'fulfilled');
  });
});

test('a refused PIN runs nothing', async () => {
  fakeCard();
  card.connect = async () => {
    throw Object.assign(new Error('Wrong PIN'), { code: 'WRONG_PIN_2' });
  };
  let ran = false;
  await assert.rejects(cieSession('12345678', async () => void (ran = true)), { code: 'WRONG_PIN_2' });
  assert.equal(ran, false);
  assert.equal(card.closed.length, 1);
});

test('the PIN is checked before the card is touched', async () => {
  fakeCard();
  await assert.rejects(cieSession('1234', async () => {}), /8 digits/);
  assert.equal(connects, 0);
  assert.equal(card.closed.length, 0);
});

test('SAVED_PIN leaves the PIN to the native side; savePin is passed through', async () => {
  fakeCard();
  const calls: [string | null, boolean][] = [];
  card.connect = async (_id, pin, save) => (calls.push([pin, save]), padded);
  await cieSession(SAVED_PIN, async () => {});
  await cieSession('12345678', async () => {}, { savePin: true });
  await cieSession('12345678', async () => {});
  assert.deepEqual(calls, [[null, false], ['12345678', true], ['12345678', false]]);
});

test('steps arrive in order, native ones included', async () => {
  fakeCard();
  card.connect = async (id) => {
    card.emit(id, 'detected');
    card.emit(id + 1, 'pin'); // another session's
    card.emit(id, 'pin');
    return padded;
  };
  const steps: string[] = [];
  await cieSession('12345678', async ({ sign }) => Promise.all([sign(digestInfo('verbale')), sign(digestInfo('allegato'))]), {
    onStep: (step) => steps.push(step),
  });
  assert.deepEqual(steps, ['detected', 'pin', 'ready', 'signing', 'signing', 'done']);
  assert.equal(card.listeners.size, 0);
});

test('late native steps and signatures after the session are not reported', async () => {
  fakeCard();
  let id = 0;
  card.connect = async (connectId) => ((id = connectId), padded);
  const steps: string[] = [];
  let late: ((digestInfo: Uint8Array) => Promise<Uint8Array>) | undefined;
  await cieSession(
    '12345678',
    async ({ sign }) => {
      card.emit(id, 'detected'); // arrives after connect resolved
      late = sign;
    },
    { onStep: (step) => steps.push(step) },
  );
  card.sign = async () => {
    throw Object.assign(new Error('Cancelled'), { code: 'CANCELLED' });
  };
  await assert.rejects(late!(digestInfo('verbale')), { code: 'CANCELLED' });
  assert.deepEqual(steps, ['ready', 'done']);
});

test('a failed session reports no done', async () => {
  fakeCard();
  const steps: string[] = [];
  await assert.rejects(
    cieSession('12345678', async () => Promise.reject(new Error('boom')), { onStep: (step) => steps.push(step) }),
    /boom/,
  );
  assert.deepEqual(steps, ['ready']);
});

test('sheet texts: defaults, overrides, done or error on close', async () => {
  fakeCard();
  const sent: Record<string, string>[] = [];
  card.connect = async (_id, _pin, _save, messages) => (sent.push(messages), padded);
  await cieSession('12345678', async () => {}, { prompt: 'Avvicina', messages: { pin: 'PIN…', done: 'Firmato', ready: undefined } });
  assert.deepEqual(sent[0], { prompt: 'Avvicina', detected: 'CIE rilevata, non allontanarla', pin: 'PIN…', ready: 'PIN verificato', signing: 'Firma in corso…' });
  assert.deepEqual(card.closed, [[card.closed[0][0], null, 'Firmato']]);
  card.closed = [];
  await assert.rejects(cieSession('12345678', async () => Promise.reject(new Error('boom')), { error: 'Errore' }));
  assert.deepEqual(card.closed.map(([, error, done]) => [error, done]), [['Errore', null]]);
});
