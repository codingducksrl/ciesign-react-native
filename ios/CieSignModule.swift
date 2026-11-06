import CoreNFC
import ExpoModulesCore
import LocalAuthentication

public class CieSignModule: Module {
  // Main-actor state. Ids come from JS; sessions up to `closed` are over, even if their connect arrives later.
  private var reader: Reader?
  private var closed = 0

  public func definition() -> ModuleDefinition {
    Name("CieSign")

    Events("onStep")

    // `messages`: NFC sheet texts by step, `prompt` first.
    AsyncFunction("connect") {
      @MainActor (id: Int, pin: String?, save: Bool, messages: [String: String], biometricPrompt: String, biometricCancel: String) async throws -> Data in
      guard NFCTagReaderSession.readingAvailable else { throw failure("NFC_UNAVAILABLE", "NFC tag reading is not available") }
      guard id > self.closed else { throw cancelled }
      self.reader?.close(nil, nil)
      let reader = Reader(id: id, messages: messages, onStep: self.reporter(id))
      self.reader = reader
      do {
        return try await reader.connect(pin: pin, save: save, biometricPrompt: biometricPrompt, biometricCancel: biometricCancel)
      } catch {
        let error = coded(reader.invalidation ?? error)
        if pin == nil, let code = (error as? Exception)?.code, code.hasPrefix("WRONG_PIN") || code == "PIN_LOCKED" { SavedPin.delete() }
        throw error
      }
    }

    AsyncFunction("sign") { @MainActor (id: Int, digestInfo: Data) async throws -> Data in
      guard let reader = self.reader, reader.id == id else { throw cancelled }
      do {
        guard let card = reader.card else { throw cancelled }  // the reason is in `invalidation`, e.g. a timeout
        reader.show("signing")
        return try await card.sign(digestInfo)
      } catch {
        throw coded(reader.invalidation ?? error)
      }
    }

    AsyncFunction("close") { @MainActor (id: Int, error: String?, done: String?) async in
      self.closed = max(self.closed, id)
      guard let reader = self.reader, reader.id <= id else { return }
      reader.close(error, done)
      self.reader = nil
    }

    AsyncFunction("pinStatus") { () -> String in
      SavedPin.isSaved ? "saved" : SavedPin.canSave ? "available" : "unavailable"
    }

    AsyncFunction("forgetPin") { SavedPin.delete() }

    OnDestroy {
      DispatchQueue.main.async { self.reader?.close(nil, nil) }
    }
  }

  /// Sends session `id`'s steps to JS as `onStep` events, without keeping the module alive.
  private func reporter(_ id: Int) -> (String) -> Void {
    { [weak self] step in self?.sendEvent("onStep", ["id": id, "step": step]) }
  }
}

/// One NFCTagReaderSession; used on the main thread only.
private final class Reader: NSObject, NFCTagReaderSessionDelegate {
  let id: Int
  private let messages: [String: String]
  private let onStep: (String) -> Void
  private var session: NFCTagReaderSession?
  private var pending: CheckedContinuation<Data, Error>?
  private var pin = ""
  private var save = false
  private var owner: Data?  // NIS of the card the saved PIN belongs to
  private var biometrics: LAContext?
  private var closed = false
  private(set) var card: CieCard?
  private(set) var invalidation: Error?

  init(id: Int, messages: [String: String], onStep: @escaping (String) -> Void) {
    self.id = id
    self.messages = messages
    self.onStep = onStep
  }

  /// Shows the NFC sheet text for `step`, if any.
  func show(_ step: String) {
    if let message = messages[step] { session?.alertMessage = message }
  }

  /// Shows `step` in the NFC sheet and reports it to JS.
  private func reach(_ step: String) {
    show(step)
    onStep(step)
  }

  /// A nil `pin` unlocks the saved one with Face ID or Touch ID; `save` saves `pin` once the card accepts it, with no
  /// prompt, since writing the Keychain item needs no authentication.
  func connect(pin: String?, save: Bool, biometricPrompt: String, biometricCancel: String) async throws -> Data {
    if let pin {
      if save, !SavedPin.canSave { throw SavedPinError.biometryUnavailable }
      (self.pin, self.save) = (pin, save)
    } else {
      let context = LAContext()
      context.localizedCancelTitle = biometricCancel
      context.localizedFallbackTitle = ""
      biometrics = context
      (self.pin, owner) = try await SavedPin.unlock(context, reason: biometricPrompt)
    }
    guard !closed else { throw cancelled }
    return try await withCheckedThrowingContinuation { continuation in
      guard let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: .main) else {
        return continuation.resume(throwing: failure("NFC_UNAVAILABLE", "NFC tag reading is not available"))
      }
      pending = continuation
      self.session = session
      show("prompt")
      session.begin()
    }
  }

  /// Ends the session; the NFC sheet shows `error` if there is one, otherwise `done` next to its checkmark.
  func close(_ error: String?, _ done: String?) {
    closed = true
    biometrics?.invalidate()
    finish(.failure(cancelled))
    if let error {
      session?.invalidate(errorMessage: error)
    } else {
      if let done { session?.alertMessage = done }
      session?.invalidate()
    }
    session = nil
    card = nil
  }

  func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

  func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
    invalidation = error
    card = nil
    finish(.failure(error))
  }

  func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
    guard tags.count == 1 else { return session.restartPolling() }
    guard case let .iso7816(tag) = tags[0] else { return finish(.failure(failure("NOT_A_CIE", "Not an ISO 7816 card"))) }
    Task { @MainActor in
      do {
        try await session.connect(to: tags[0])
        reach("detected")
        let card = CieCard { apdu in
          guard let command = NFCISO7816APDU(data: apdu) else { throw failure("CARD_ERROR", "Malformed APDU") }
          let (data, sw1, sw2) = try await tag.sendCommand(apdu: command)
          return data + [sw1, sw2]
        }
        let serviceId = try await card.serviceId()
        if let owner, owner != serviceId { throw SavedPinError.otherCard }
        reach("pin")
        try await card.open(pin: pin)
        if save { try SavedPin.store(pin, card: serviceId) }
        let certificate = try await card.certificate()
        self.card = card
        show("ready")  // JS reports `ready` once connect resolves
        finish(.success(certificate))
      } catch let error as NFCReaderError where error.code == .readerTransceiveErrorSessionInvalidated {
        // didInvalidateWithError follows with the reason (cancel, timeout).
      } catch {
        finish(.failure(error))
      }
    }
  }

  private func finish(_ result: Result<Data, Error>) {
    pending?.resume(with: result)
    pending = nil
  }
}

private func failure(_ code: String, _ description: String) -> Exception {
  Exception(name: code, description: description, code: code)
}

private var cancelled: Exception { failure("CANCELLED", "Cancelled") }

private func coded(_ error: Error) -> Error {
  switch error {
  case let error as Exception: return error
  case CieCardError.wrongPin(let attemptsLeft): return failure("WRONG_PIN_\(attemptsLeft)", "Wrong PIN")
  case CieCardError.pinLocked: return failure("PIN_LOCKED", "PIN locked: unlock it with the PUK")
  case CieCardError.notCie: return failure("NOT_A_CIE", "Not a CIE")
  case SavedPinError.notSaved: return failure("PIN_NOT_SAVED", "No saved PIN")
  case SavedPinError.otherCard: return failure("WRONG_CARD", "Not the card the PIN was saved for")
  case SavedPinError.biometryUnavailable: return failure("BIOMETRIC_UNAVAILABLE", "Face ID or Touch ID is not available")
  case SavedPinError.cancelled: return cancelled
  case let error as NFCReaderError:
    switch error.code {
    case .readerSessionInvalidationErrorUserCanceled, .readerTransceiveErrorSessionInvalidated: return cancelled
    case .readerSessionInvalidationErrorSessionTimeout: return failure("TIMEOUT", "NFC session timed out")
    case .readerSessionInvalidationErrorSystemIsBusy: return failure("BUSY", "NFC is busy, retry")
    case .readerTransceiveErrorTagConnectionLost, .readerTransceiveErrorTagResponseError, .readerTransceiveErrorTagNotConnected:
      return failure("TAG_LOST", "Card connection lost")
    default: return failure("CARD_ERROR", error.localizedDescription)
    }
  default: return failure("CARD_ERROR", "\(error)")
  }
}
