import CoreNFC
import CryptoKit
import ExpoModulesCore

public class CieSignModule: Module {
  // Main-actor state. Ids come from JS; sessions up to `closed` are over, even if their connect arrives later.
  private var reader: Reader?
  private var closed = 0

  public func definition() -> ModuleDefinition {
    Name("CieSign")

    AsyncFunction("sha256") { (data: Data) in Data(SHA256.hash(data: data)) }

    AsyncFunction("connect") { @MainActor (id: Int, pin: String, prompt: String) async throws -> Data in
      guard NFCTagReaderSession.readingAvailable else { throw failure("NFC_UNAVAILABLE", "NFC tag reading is not available") }
      guard id > self.closed else { throw cancelled }
      self.reader?.close(nil)
      let reader = Reader(id: id)
      self.reader = reader
      do {
        return try await reader.connect(pin: pin, prompt: prompt)
      } catch {
        throw coded(reader.invalidation ?? error)
      }
    }

    AsyncFunction("sign") { @MainActor (id: Int, digestInfo: Data) async throws -> Data in
      guard let reader = self.reader, reader.id == id, let card = reader.card else { throw cancelled }
      do {
        return try await card.sign(digestInfo)
      } catch {
        throw coded(reader.invalidation ?? error)
      }
    }

    AsyncFunction("close") { @MainActor (id: Int, error: String?) async in
      self.closed = max(self.closed, id)
      guard let reader = self.reader, reader.id <= id else { return }
      reader.close(error)
      self.reader = nil
    }

    OnDestroy {
      DispatchQueue.main.async { self.reader?.close(nil) }
    }
  }
}

/// One NFCTagReaderSession; used on the main thread only.
private final class Reader: NSObject, NFCTagReaderSessionDelegate {
  let id: Int
  private var session: NFCTagReaderSession?
  private var pending: CheckedContinuation<Data, Error>?
  private var pin = ""
  private(set) var card: CieCard?
  private(set) var invalidation: Error?

  init(id: Int) {
    self.id = id
  }

  func connect(pin: String, prompt: String) async throws -> Data {
    self.pin = pin
    return try await withCheckedThrowingContinuation { continuation in
      guard let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: .main) else {
        return continuation.resume(throwing: failure("NFC_UNAVAILABLE", "NFC tag reading is not available"))
      }
      pending = continuation
      self.session = session
      session.alertMessage = prompt
      session.begin()
    }
  }

  func close(_ error: String?) {
    finish(.failure(cancelled))
    if let error { session?.invalidate(errorMessage: error) } else { session?.invalidate() }
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
        let card = CieCard { apdu in
          guard let command = NFCISO7816APDU(data: apdu) else { throw failure("CARD_ERROR", "Malformed APDU") }
          let (data, sw1, sw2) = try await tag.sendCommand(apdu: command)
          return data + [sw1, sw2]
        }
        try await card.open(pin: pin)
        let certificate = try await card.certificate()
        self.card = card
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
