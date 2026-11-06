# ciesign-react-native

RSA signatures with the Italian electronic identity card (CIE 3.0) over NFC, for React Native. The library reads the card certificate and returns raw signatures; packaging them (PAdES, CAdES, XAdES…) is up to your code or your server.

- One NFC tap and one PIN check, then as many signatures as you need. The card verifies the 8-digit PIN and signs with its PIN-protected key (RSA PKCS#1 v1.5); each signature is checked against the card certificate before it is returned.
- Optionally, the PIN is saved behind Face ID, Touch ID or a fingerprint, protected by the Secure Enclave or the Android Keystore's secure hardware.

A CIE signature is an advanced electronic signature (FEA), not a qualified one (FEQ/firma digitale). Validators don't trust the CIE CA by default, so recipients see an unknown signer until they trust it.

> **Status:** not yet tested with a physical CIE, nor several signatures in one session. The iOS card protocol was compared byte by byte with PagoPA's Android SDK on a simulated card.

## Install

Requires iOS 16.4 or later, or an Android device with NFC. Expo module: it needs a development build (not Expo Go). Bare React Native apps need [Expo modules](https://docs.expo.dev/bare/installing-expo-modules/).

```sh
npx expo install ciesign-react-native
```

```json
{ "expo": { "plugins": ["ciesign-react-native"] } }
```

The config plugin sets up iOS: the NFC tag reading entitlement, `NFCReaderUsageDescription` and `NSFaceIDUsageDescription` (override them with `["ciesign-react-native", { "nfcUsageDescription": "…", "faceIdUsageDescription": "…" }]`; existing values are kept) and the ISO 7816 application IDs. Without the plugin, add them by hand:

```xml
<!-- *.entitlements -->
<key>com.apple.developer.nfc.readersession.formats</key>
<array><string>TAG</string></array>

<!-- Info.plist -->
<key>NFCReaderUsageDescription</key>
<string>…</string>
<key>NSFaceIDUsageDescription</key> <!-- saved PIN only -->
<string>…</string>
<!-- keep this order -->
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
import { cieSession } from 'ciesign-react-native';

// DER DigestInfo of a SHA-256 hash: the algorithm prefix, then the 32-byte hash
const SHA256 = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
const digestInfo = (hash: Uint8Array) => Uint8Array.from([...SHA256, ...hash]);

const signatures = await cieSession(pin, async ({ certificate, sign }) => {
  // e.g. CMS signed attributes, which reference the certificate
  const hashes = await Promise.all(documents.map((document) => hashToSign(document, certificate)));
  return Promise.all(hashes.map((hash) => sign(digestInfo(hash))));
});
```

Inputs and outputs are `Uint8Array`. The promise stays pending until the card is tapped.

| Export | |
|---|---|
| `cieSession(pin, use, { prompt?, error?, savePin?, biometricPrompt?, biometricCancel? })` | Waits for the card and verifies the PIN, then resolves to what `use({ certificate, sign })` resolves to. The NFC session ends when `use` settles: the card must stay on the phone until then. `pin` is the 8-digit PIN or `SAVED_PIN`. `prompt` and `error` are the iOS NFC sheet texts; the others are explained under [Saved PIN](#saved-pin). |
| `certificate` | The card's DER authentication certificate: holder name and fiscal code are in its subject. |
| `sign(digestInfo)` | RSA PKCS#1 v1.5 signature (the card adds the padding) of a DER DigestInfo, checked against `certificate`. Call it as often as needed while `use` runs; calls run one at a time, in order. |
| `SAVED_PIN`, `pinStatus()`, `forgetPin()` | See [Saved PIN](#saved-pin). |
| `cancel()` | Aborts the session in progress. Android has no system NFC sheet, so give users a cancel button. |

iOS ends an NFC session 60 seconds after it starts, `use` included: prepare what does not depend on the certificate, such as a PDF's byte range, before calling `cieSession`.

A PIN that is not 8 digits throws a plain `Error`. Card errors carry a `code`:

| Code | Meaning |
|---|---|
| `WRONG_PIN_2`, `WRONG_PIN_1` | Wrong PIN, attempts left. Don't retry automatically. |
| `PIN_LOCKED` | Three wrong PINs: the card needs the PUK. |
| `NOT_A_CIE` | The tag is not a CIE. |
| `TAG_LOST` | The card moved away during the operation. |
| `CANCELLED` | `cancel()`, a newer session started, `sign` called after `use` settled, or the user closed the iOS sheet or the biometric prompt. |
| `TIMEOUT` | iOS ends NFC sessions after 60 seconds. |
| `BUSY` | iOS is still closing the previous NFC session: retry. |
| `NFC_UNAVAILABLE` | No NFC, or, on Android, NFC turned off or no foreground activity. |
| `CARD_ERROR` | Any other card or protocol failure, including a signature that does not verify against the card certificate. |
| `PIN_NOT_SAVED` | `SAVED_PIN`, but no PIN is saved, or it was deleted because the enrolled biometrics changed or the device passcode was removed. Ask for the PIN. |
| `WRONG_CARD` | `SAVED_PIN`, but the card is not the one the PIN was saved for. The PIN was not sent. |
| `BIOMETRIC_UNAVAILABLE` | `SAVED_PIN` or `savePin` without a usable strong biometric: locked out after failed attempts, Face ID denied to the app, no secure hardware, or, for `savePin`, none enrolled. On Android, also when the activity is not a `FragmentActivity`. |

On Android the app must stay in the foreground while the card is read.

### Saved PIN

Optional: apps that always pass the PIN don't need any of this. With `savePin`, the typed PIN is saved once the card accepts it. Later operations pass `SAVED_PIN`, which asks for Face ID, Touch ID or a fingerprint instead of the PIN.

A biometric prompt appears only where the secure hardware requires one: to unlock on both platforms, and to save on Android, where the Keystore key encrypts only after a biometric. iOS saves with no prompt, because writing a Keychain item needs no authentication. Prompts come before the card is read; `biometricPrompt` and `biometricCancel` set their texts.

```ts
import { SAVED_PIN, cieSession, pinStatus } from 'ciesign-react-native';

const status = await pinStatus(); // 'saved' | 'available' | 'unavailable'
const signatures =
  status === 'saved'
    ? await cieSession(SAVED_PIN, use, { biometricPrompt: 'Firma i verbali' })
    : await cieSession(pin, use, { savePin: status === 'available' && userWantsBiometrics });
```

- **Biometrics only.** iOS: a Keychain item with `.biometryCurrentSet`, available only while a passcode is set, never synced, backed up or moved to another device. Android: an AES-256-GCM Keystore key, in StrongBox when the device has it, otherwise in the TEE (software keys are refused). It encrypts and decrypts only right after a Class 3 biometric, through `BiometricPrompt` with a `CryptoObject`; the encrypted PIN is in `noBackupFilesDir`. The device passcode never unlocks it, and on Android face unlock only counts where it is Class 3.
- **Cancelling the prompt cancels the operation** (`CANCELLED`): nothing is read or signed. After `CANCELLED` or `BIOMETRIC_UNAVAILABLE`, ask for the PIN, or retry without `savePin` to sign without saving.
- **Enrolling a new face or finger deletes it**, and so does removing one on iOS, or all of them on Android, or turning off the device passcode (`PIN_NOT_SAVED` on the next use).
- **Saved only after the card accepts it**, and deleted on `WRONG_PIN_*` or `PIN_LOCKED`: a PIN changed elsewhere costs one attempt, not three.
- **Bound to its card.** The card's NIS (EF 1001), readable without the PIN, is checked first: another CIE gets `WRONG_CARD` and never sees the PIN.
- **Native only.** A saved PIN is decrypted in native code and sent to the card; it never reaches JavaScript.
- One PIN per app: saving again replaces it. `forgetPin()` deletes it. `savePin` fails with `BIOMETRIC_UNAVAILABLE` before the card is read when `pinStatus()` is `'unavailable'`.

## How it works

`cieSession` opens one NFC session: NIS read (EF 1001), secure messaging (Diffie-Hellman and device authentication), PIN verification, certificate read (EF 1003). Each `sign` then sends `MSE SET` (key `0x81`, RSA PKCS#1) and `INTERNAL AUTHENTICATE` with the DigestInfo over the same secure channel.

- Android drives `CieCommands` from PagoPA's [`cie-sdk-android`](https://github.com/pagopa/cie-sdk-android) through a Java shim, because the class is Kotlin-internal. The dependency is pinned to `0.1.11`: check the shim before upgrading.
- iOS implements the same protocol in `ios/CieCard.swift`, derived from PagoPA's [`cie-sdk-ios`](https://github.com/pagopa/cie-sdk-ios), whose signing code is not public.

## Development

Needs Node.js 24 and OpenSSL.

```sh
npm install
npm test   # simulates the card with a throwaway RSA key made by OpenSSL
```

`npm test` covers the JavaScript side only: try changes to `ios/` and `android/` in a development build with a real CIE.

Issues and pull requests are welcome, especially reports from physical cards. Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Legal

If your customers sign with the CIE in their dealings with you, you are an FEA provider under DPCM 22/02/2013 art. 55 c.2 lett. a, with the obligations of art. 57 (identification, information, insurance, 20-year retention). Get legal advice before offering CIE signing to third parties.

## License

[MIT](LICENSE). `ios/CieCard.swift` is derived from PagoPA's [`cie-sdk-ios`](https://github.com/pagopa/cie-sdk-ios), also MIT.
