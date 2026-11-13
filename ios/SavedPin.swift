import Foundation
import LocalAuthentication
import Security

enum SavedPinError: Error {
  case notSaved, otherCard, biometryUnavailable, cancelled
}

/// The CIE PIN as a Keychain item that the Secure Enclave releases only after Face ID or Touch ID matches one of the
/// faces or fingers enrolled when it was saved. It is never synced, backed up or restored to another device. Next to it,
/// its card's certificate: public, so readable without biometrics, and replaced or deleted with the PIN.
enum SavedPin {
  private static let item: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: "it.codingduck.ciesign.pin"]
  private static let certificateItem: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: "it.codingduck.ciesign.certificate"]

  static var canSave: Bool { LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) }

  /// Checks for the item without showing any UI.
  static var isSaved: Bool {
    let context = LAContext()
    context.interactionNotAllowed = true
    let status = SecItemCopyMatching(item.merging([kSecUseAuthenticationContext: context]) { $1 } as CFDictionary, nil)
    return status == errSecSuccess || status == errSecInteractionNotAllowed
  }

  /// Replaces the saved PIN; `card` is the NIS of the card that accepted it.
  static func store(_ pin: String, card: Data) throws {
    delete()
    guard let access = access(),
          SecItemAdd(item.merging([kSecAttrAccessControl: access, kSecAttrGeneric: card, kSecValueData: Data(pin.utf8)]) { $1 } as CFDictionary, nil)
            == errSecSuccess
    else { throw SavedPinError.biometryUnavailable }
  }

  /// Evaluates the item's access control, which the Keychain read then requires; invalidating `context` cancels it.
  private static func authenticate(_ context: LAContext, reason: String) async throws {
    do {
      guard let access = access(), try await context.evaluateAccessControl(access, operation: .useItem, localizedReason: reason) else {
        throw SavedPinError.biometryUnavailable
      }
    } catch let error as LAError {
      switch error.code {
      case .userCancel, .appCancel, .systemCancel, .userFallback: throw SavedPinError.cancelled
      case .biometryNotEnrolled:  // removing every face or finger invalidated the item
        delete()
        throw SavedPinError.notSaved
      default: throw SavedPinError.biometryUnavailable
      }
    }
  }

  /// Authenticates with `context` and returns the PIN with its card's NIS.
  static func unlock(_ context: LAContext, reason: String) async throws -> (pin: String, card: Data) {
    guard isSaved else { throw SavedPinError.notSaved }
    try await authenticate(context, reason: reason)
    context.interactionNotAllowed = true
    var result: CFTypeRef?
    let query = item.merging([kSecUseAuthenticationContext: context, kSecReturnData: true, kSecReturnAttributes: true]) { $1 }
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let found = result as? [CFString: Any],
          let pin = found[kSecValueData] as? Data, let card = found[kSecAttrGeneric] as? Data
    else {
      delete()  // the enrolled faces or fingers changed since the PIN was saved
      throw SavedPinError.notSaved
    }
    return (String(decoding: pin, as: UTF8.self), card)
  }

  /// Saves the certificate file of the card whose PIN is saved; `card` is its NIS. Best effort: without it, sessions read
  /// the certificate from the card.
  static func storeCertificate(_ certificate: Data, card: Data) {
    SecItemDelete(certificateItem as CFDictionary)
    let attributes: [CFString: Any] = [kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAttrGeneric: card, kSecValueData: certificate]
    SecItemAdd(certificateItem.merging(attributes) { $1 } as CFDictionary, nil)
  }

  /// The certificate file saved with the PIN and its card's NIS, without any UI; nil when none is saved.
  static func certificate() -> (certificate: Data, card: Data)? {
    guard isSaved else { return nil }
    var result: CFTypeRef?
    let query = certificateItem.merging([kSecReturnData: true, kSecReturnAttributes: true]) { $1 }
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let found = result as? [CFString: Any],
          let certificate = found[kSecValueData] as? Data, let card = found[kSecAttrGeneric] as? Data
    else { return nil }
    return (certificate, card)
  }

  static func delete() {
    SecItemDelete(item as CFDictionary)
    SecItemDelete(certificateItem as CFDictionary)
  }

  private static func access() -> SecAccessControl? {
    SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, nil)
  }
}
