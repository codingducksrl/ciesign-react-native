package it.codingduck.ciesign;

import it.pagopa.io.app.cie.cie.NfcEvent;
import it.pagopa.io.app.cie.cie.OnTransmit;
import it.pagopa.io.app.cie.cie.commands.CieCommands;

/** PagoPA's CieCommands is Kotlin-internal: public in bytecode, so Java can call it and Kotlin cannot. */
final class CieCard {
  private final CieCommands commands;

  CieCard(OnTransmit transmit) {
    commands = new CieCommands(transmit);
  }

  /** Opens secure messaging, verifies the PIN and returns the certificate file (EF 1003, zero padded). */
  byte[] open(String pin) throws Exception {
    commands.getServiceID();
    commands.startSecureChannel(pin);
    return commands.readCertCie();
  }

  /** RSA signature of a DigestInfo with the PIN-protected key; the card adds the PKCS#1 v1.5 padding. */
  byte[] sign(byte[] digestInfo) throws Exception {
    return commands.sign(digestInfo, NfcEvent.SIGN);
  }
}
