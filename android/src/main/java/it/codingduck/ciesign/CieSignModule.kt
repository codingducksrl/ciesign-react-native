package it.codingduck.ciesign

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import it.pagopa.io.app.cie.cie.ApduResponse
import it.pagopa.io.app.cie.cie.CieSdkException
import it.pagopa.io.app.cie.cie.NfcError
import it.pagopa.io.app.cie.cie.NfcEvent
import it.pagopa.io.app.cie.cie.OnTransmit
import java.io.IOException
import java.security.MessageDigest

class CieSignModule : Module() {
  // Session state, guarded by `lock`. Ids come from JS; sessions up to `closed` are over, even if their connect arrives later.
  private val lock = Any()
  private var session = 0
  private var closed = 0
  private var pending: Promise? = null
  private var tag: IsoDep? = null
  private var card: CieCard? = null

  override fun definition() = ModuleDefinition {
    Name("CieSign")

    AsyncFunction("sha256") { data: ByteArray -> MessageDigest.getInstance("SHA-256").digest(data) }

    AsyncFunction("connect") { id: Int, pin: String, _: String, promise: Promise ->
      val activity = appContext.currentActivity ?: throw CodedException("NFC_UNAVAILABLE", "No foreground activity", null)
      val adapter = NfcAdapter.getDefaultAdapter(activity)
      if (adapter?.isEnabled != true) throw CodedException("NFC_UNAVAILABLE", "NFC is missing or turned off", null)
      synchronized(lock) {
        if (id <= closed) throw cancelled()
        end()
        session = id
        pending = promise
      }
      val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
      adapter.enableReaderMode(activity, { onTag(it, id, pin) }, flags, null)
    }

    AsyncFunction("sign") { id: Int, digestInfo: ByteArray ->
      val card = synchronized(lock) { card.takeIf { session == id } } ?: throw cancelled()
      try {
        card.sign(digestInfo)
      } catch (e: Exception) {
        throw if (synchronized(lock) { session != id }) cancelled() else coded(e)
      }
    }

    Function("close") { id: Int, _: String? ->
      synchronized(lock) {
        closed = maxOf(closed, id)
        if (session in 1..id) end()
      }
    }

    OnDestroy { synchronized(lock) { end() } }
  }

  // Runs on the NFC thread; the tag stays connected after returning, until the session ends.
  private fun onTag(discovered: Tag, id: Int, pin: String) {
    val promise = synchronized(lock) { pending.takeIf { session == id }.also { if (it != null) pending = null } } ?: return
    var pinStatus = 0
    try {
      val isoDep = IsoDep.get(discovered) ?: throw CodedException("NOT_A_CIE", "Not an ISO 14443-4 card", null)
      isoDep.timeout = 10_000
      isoDep.connect()
      synchronized(lock) {
        if (session != id) {
          isoDep.close()
          throw cancelled()
        }
        tag = isoDep
      }
      val c = CieCard(object : OnTransmit {
        override fun sendCommand(apdu: ByteArray, nfcEvents: NfcEvent): ApduResponse {
          val response = isoDep.transceive(apdu)
          if (nfcEvents == NfcEvent.VERIFY_PIN) pinStatus = status(response)
          return ApduResponse(response)
        }

        override fun error(error: NfcError) = Unit
      })
      val certificate = c.open(pin)
      synchronized(lock) {
        if (session != id) throw cancelled()
        card = c
      }
      promise.resolve(certificate)
    } catch (e: Exception) {
      promise.reject(if (synchronized(lock) { session != id }) cancelled() else coded(e, pinStatus))
    }
  }

  private fun end() {
    pending?.reject(cancelled())
    pending = null
    card = null
    runCatching { tag?.close() }
    tag = null
    session = 0
    appContext.currentActivity?.let { NfcAdapter.getDefaultAdapter(it)?.disableReaderMode(it) }
  }

  private fun cancelled() = CodedException("CANCELLED", "Cancelled", null)

  // Under secure messaging the card's status word is in DO 99, ahead of the MAC; otherwise it ends the response.
  private fun status(response: ByteArray): Int {
    val i = if (response.size >= 4 && response[0] == 0x99.toByte() && response[1] == 0x02.toByte()) 2 else response.size - 2
    return ((response[i].toInt() and 0xFF) shl 8) or (response[i + 1].toInt() and 0xFF)
  }

  // PagoPA's SDK reports any unexpected VERIFY status as PIN_BLOCKED, so the status word decides.
  private fun coded(e: Exception, pinStatus: Int = 0): CodedException {
    val error = (e as? CieSdkException)?.getError()
    return when {
      e is CodedException -> e
      error == NfcError.WRONG_PIN || error == NfcError.PIN_BLOCKED -> when {
        pinStatus == 0x6983 || pinStatus == 0x63C0 -> CodedException("PIN_LOCKED", "PIN locked: unlock it with the PUK", e)
        (pinStatus and 0xFFF0) == 0x63C0 -> CodedException("WRONG_PIN_${pinStatus and 0xF}", "Wrong PIN", e)
        else -> CodedException("CARD_ERROR", "PIN verification failed: %04X".format(pinStatus), e)
      }
      error == NfcError.NOT_A_CIE -> CodedException("NOT_A_CIE", "Not a CIE", e)
      e is IOException || e is SecurityException -> CodedException("TAG_LOST", "Card connection lost", e)
      else -> CodedException("CARD_ERROR", error?.name ?: e.message ?: e.toString(), e)
    }
  }
}
