# ciesign-react-native

PAdES and CAdES (`.p7m`) signatures with the Italian electronic identity card (CIE 3.0) over NFC, for React Native.

- **PAdES** baseline B-B (`ETSI.CAdES.detached`), invisible, appended as an incremental update: earlier signatures stay valid, so a document can be signed by several people.
- **CAdES-BES** enveloping `.p7m` (DER), with the attributes the official CIE software writes: content-type, signing-time, message-digest, signing-certificate-v2.
- One NFC tap per signature. The card verifies the 8-digit PIN and signs with its PIN-protected key; the signature is checked against the card certificate before it is embedded.
- Optionally, the PIN is saved behind Face ID, Touch ID or a fingerprint, protected by the Secure Enclave or the Android Keystore's secure hardware.

A CIE signature is an advanced electronic signature (FEA), not a qualified one (FEQ/firma digitale). Validators don't trust the CIE CA by default, so recipients see an unknown signer until they trust it.

> **Status:** not yet tested with a physical CIE. The PDF/CMS output is checked with OpenSSL, pyHanko and poppler; the iOS card protocol is checked byte by byte against PagoPA's Android SDK on a simulated card.

## Install

Expo module: it needs a development build (not Expo Go). Bare React Native apps need [Expo modules](https://docs.expo.dev/bare/installing-expo-modules/).

```sh
npx expo install ciesign-react-native
```

```json
{ "expo": { "plugins": ["ciesign-react-native"] } }
```

The config plugin sets up iOS: the NFC tag reading entitlement, `NFCReaderUsageDescription` and `NSFaceIDUsageDescription` (override them with `["ciesign-react-native", { "nfcUsageDescription": "…", "faceIdUsageDescription": "…" }]`) and the ISO 7816 application IDs. Without the plugin, add them by hand:

```xml
<!-- *.entitlements -->
<key>com.apple.developer.nfc.readersession.formats</key>
<array><string>TAG</string></array>
<!-- Info.plist: keep this order -->
<key>com.apple.developer.nfc.readersession.iso7816.select-identifiers</key>
<array>
  <string>A0000002471001</string>
  <string>A0000000308000000009816001</string>
  <string>A00000000039</string>
  <string>A0000002472001</string>
  <string>00000000000000</string>
</array>
```

Android needs nothing: the `NFC` and biometric permissions come with the library.

## Use

```ts
import { cieSigner, signCades, signPades } from 'ciesign-react-native';

const signedPdf = await signPades(pdfBytes, cieSigner(pin), { reason: 'Approvazione verbale', location: 'Bologna' });
const p7m = await signCades(fileBytes, cieSigner(pin));
```

Inputs and outputs are `Uint8Array`. The promise stays pending until the card is tapped.

| Export | |
|---|---|
| `signPades(pdf, signer, { reason?, location?, contactInfo? })` | Signed PDF. Encrypted PDFs and PDFs certified against any change are rejected. |
| `signCades(content, signer)` | `.p7m` file content. |
| `cieSigner(pin, { prompt?, error?, savePin?, biometricPrompt?, biometricCancel? })` | Signer backed by the CIE. `pin` is the 8-digit PIN or `SAVED_PIN`. `prompt` and `error` are the iOS NFC sheet texts; the others are explained under [Saved PIN](#saved-pin). |
| `readCertificate(pin, options?)` | The card's DER certificate (holder name and fiscal code are in its subject). Same `pin` and options as `cieSigner`. |
| `SAVED_PIN`, `pinStatus()`, `forgetPin()` | See [Saved PIN](#saved-pin). |
| `cancel()` | Aborts the operation in progress, also while the document is still being prepared. Signers created before the call stay cancelled. Android has no system NFC sheet, so give users a cancel button. |
| `Signer` | `(toBeSigned: (certificate) => Promise<digestInfo>) => Promise<signature>`: implement it to sign the same way with another key, e.g. a remote signing service. |

Errors carry a `code`:

| Code | Meaning |
|---|---|
| `WRONG_PIN_2`, `WRONG_PIN_1` | Wrong PIN, attempts left. Don't retry automatically. |
| `PIN_LOCKED` | Three wrong PINs: the card needs the PUK. |
| `NOT_A_CIE` | The tag is not a CIE. |
| `TAG_LOST` | The card moved away during the operation. |
| `CANCELLED` | `cancel()`, a newer CIE operation started, or the user closed the iOS sheet or the biometric prompt. |
| `TIMEOUT` | iOS ends NFC sessions after 60 seconds. |
| `BUSY` | iOS is still closing the previous NFC session: retry. |
| `NFC_UNAVAILABLE` | No NFC, or NFC turned off (Android). |
| `CARD_ERROR` | Any other card or protocol failure, including a signature that does not verify against the card certificate. |
| `PIN_NOT_SAVED` | `SAVED_PIN`, but no PIN is saved, or it was deleted because the enrolled biometrics changed. Ask for the PIN. |
| `WRONG_CARD` | `SAVED_PIN`, but the card is not the one the PIN was saved for. The PIN was not sent. |
| `BIOMETRIC_UNAVAILABLE` | `SAVED_PIN` or `savePin` without a usable strong biometric: none enrolled, locked out after failed attempts, Face ID denied to the app, or no secure hardware. |

On Android the app must stay in the foreground while the card is read.

### Saved PIN

Optional: apps that always pass the PIN don't need any of this. With `savePin`, the typed PIN is saved once the card accepts it. Later operations pass `SAVED_PIN`, which asks for Face ID, Touch ID or a fingerprint instead of the PIN.

A biometric prompt appears only where the secure hardware requires one: to unlock on both platforms, and to save on Android, where the Keystore key encrypts only after a biometric. iOS saves with no prompt, because writing a Keychain item needs no authentication. Prompts come before the card is read; `biometricPrompt` and `biometricCancel` set their texts.

```ts
import { SAVED_PIN, cieSigner, pinStatus, signPades } from 'ciesign-react-native';

const status = await pinStatus(); // 'saved' | 'available' | 'unavailable'
const signer =
  status === 'saved'
    ? cieSigner(SAVED_PIN, { biometricPrompt: 'Firma il verbale' })
    : cieSigner(pin, { savePin: status === 'available' && userWantsBiometrics });
const signedPdf = await signPades(pdfBytes, signer);
```

- **Biometrics only.** iOS: a Keychain item with `.biometryCurrentSet`, available only while a passcode is set, never synced, backed up or moved to another device. Android: an AES-256-GCM Keystore key, in StrongBox when the device has it, otherwise in the TEE (software keys are refused). It encrypts and decrypts only right after a Class 3 biometric, through `BiometricPrompt` with a `CryptoObject`; the encrypted PIN is in `noBackupFilesDir`. The device passcode never unlocks it, and on Android face unlock only counts where it is Class 3.
- **Cancelling the prompt cancels the operation** (`CANCELLED`): nothing is read or signed. After `CANCELLED` or `BIOMETRIC_UNAVAILABLE`, ask for the PIN, or retry without `savePin` to sign without saving.
- **Enrolling a new face or finger deletes it**, and so does removing one on iOS, or all of them on Android (`PIN_NOT_SAVED` on the next use).
- **Saved only after the card accepts it**, and deleted on `WRONG_PIN_*` or `PIN_LOCKED`: a PIN changed elsewhere costs one attempt, not three.
- **Bound to its card.** The card's NIS (EF 1001), readable without the PIN, is checked first: another CIE gets `WRONG_CARD` and never sees the PIN.
- **Native only.** A saved PIN is decrypted in native code and sent to the card; it never reaches JavaScript.
- One PIN per app: saving again replaces it. `forgetPin()` deletes it. `savePin` fails with `BIOMETRIC_UNAVAILABLE` before the card is read when `pinStatus()` is `'unavailable'`.

## How it works

`signPades`/`signCades` hash the content, then call the signer. The CIE signer opens one NFC session: NIS read (EF 1001), secure messaging (Diffie-Hellman and device authentication), PIN verification, certificate read (EF 1003), then `MSE SET` (key `0x81`, RSA PKCS#1) and `INTERNAL AUTHENTICATE` with the SHA-256 DigestInfo of the CMS signed attributes.

- Android drives `CieCommands` from PagoPA's [`cie-sdk-android`](https://github.com/pagopa/cie-sdk-android) through a Java shim, because the class is Kotlin-internal. The dependency is pinned to `0.1.11`: check the shim before upgrading.
- iOS implements the same protocol in `ios/CieCard.swift`, derived from PagoPA's [`cie-sdk-ios`](https://github.com/pagopa/cie-sdk-ios), whose signing code is not public.
- PDF parsing and the incremental update use [`@cantoo/pdf-lib`](https://github.com/cantoo-scribe/pdf-lib); CMS is encoded directly in `src/cms.ts`.

## Development

```sh
npm install
npm test   # signs with a throwaway RSA key and verifies with OpenSSL
```

## Legal

If your customers sign with the CIE in their dealings with you, you are an FEA provider under DPCM 22/02/2013 art. 55 c.2 lett. a, with the obligations of art. 57 (identification, information, insurance, 20-year retention). Get legal advice before offering CIE signing to third parties.
