const { withEntitlementsPlist, withInfoPlist } = require('expo/config-plugins');

// iOS tries these AIDs in order when a card is detected; this order is the one known to work with the CIE.
const AIDS = ['A0000002471001', 'A0000000308000000009816001', 'A00000000039', 'A0000002472001', '00000000000000'];
const SELECT_IDENTIFIERS = 'com.apple.developer.nfc.readersession.iso7816.select-identifiers';
const FORMATS = 'com.apple.developer.nfc.readersession.formats';

module.exports = (
  config,
  {
    nfcUsageDescription = 'La CIE viene letta via NFC per firmare documenti.',
    faceIdUsageDescription = 'Face ID sblocca il PIN della CIE salvato sul dispositivo.',
  } = {},
) => {
  config = withEntitlementsPlist(config, (c) => {
    c.modResults[FORMATS] = [...new Set([...(c.modResults[FORMATS] ?? []), 'TAG'])];
    return c;
  });
  return withInfoPlist(config, (c) => {
    c.modResults.NFCReaderUsageDescription ??= nfcUsageDescription;
    c.modResults.NSFaceIDUsageDescription ??= faceIdUsageDescription;
    c.modResults[SELECT_IDENTIFIERS] = [...new Set([...(c.modResults[SELECT_IDENTIFIERS] ?? []), ...AIDS])];
    return c;
  });
};
