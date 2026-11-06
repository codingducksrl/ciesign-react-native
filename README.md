# ciesign-react-native

PAdES and CAdES (`.p7m`) signatures with the Italian electronic identity card (CIE 3.0) over NFC, for React Native.

- **PAdES** baseline B-B (`ETSI.CAdES.detached`), invisible, appended as an incremental update: earlier signatures stay valid, so a document can be signed by several people.
- **CAdES-BES** enveloping `.p7m` (DER), with the attributes the official CIE software writes: content-type, signing-time, message-digest, signing-certificate-v2.
- One NFC tap per signature. The card verifies the 8-digit PIN and signs with its PIN-protected key; the signature is checked against the card certificate before it is embedded.

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

The config plugin sets up iOS: the NFC tag reading entitlement, `NFCReaderUsageDescription` (override it with `["ciesign-react-native", { "nfcUsageDescription": "…" }]`) and the ISO 7816 application IDs. Without the plugin, add them by hand:

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

Android needs nothing: the `NFC` permission comes with the library.

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
| `cieSigner(pin, { prompt?, error? })` | Signer backed by the CIE. `prompt` and `error` are the iOS NFC sheet texts. |
| `readCertificate(pin, options?)` | The card's DER certificate (holder name and fiscal code are in its subject). |
| `cancel()` | Aborts the operation in progress, also while the document is still being prepared. Signers created before the call stay cancelled. Android has no system NFC sheet, so give users a cancel button. |
| `Signer` | `(toBeSigned: (certificate) => Promise<digestInfo>) => Promise<signature>`: implement it to sign the same way with another key, e.g. a remote signing service. |

Errors carry a `code`:

| Code | Meaning |
|---|---|
| `WRONG_PIN_2`, `WRONG_PIN_1` | Wrong PIN, attempts left. Don't retry automatically. |
| `PIN_LOCKED` | Three wrong PINs: the card needs the PUK. |
| `NOT_A_CIE` | The tag is not a CIE. |
| `TAG_LOST` | The card moved away during the operation. |
| `CANCELLED` | `cancel()`, a newer CIE operation started, or the user closed the iOS sheet. |
| `TIMEOUT` | iOS ends NFC sessions after 60 seconds. |
| `BUSY` | iOS is still closing the previous NFC session: retry. |
| `NFC_UNAVAILABLE` | No NFC, or NFC turned off (Android). |
| `CARD_ERROR` | Any other card or protocol failure, including a signature that does not verify against the card certificate. |

On Android the app must stay in the foreground while the card is read.

## How it works

`signPades`/`signCades` hash the content, then call the signer. The CIE signer opens one NFC session: secure messaging (Diffie-Hellman and device authentication), PIN verification, certificate read (EF 1003), then `MSE SET` (key `0x81`, RSA PKCS#1) and `INTERNAL AUTHENTICATE` with the SHA-256 DigestInfo of the CMS signed attributes.

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
