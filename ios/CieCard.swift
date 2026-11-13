// Derived from PagoPA cie-sdk-ios (https://github.com/pagopa/cie-sdk-ios), MIT License, Copyright (c) 2025 PagoPA S.p.A.

import CommonCrypto
import CryptoKit
import Foundation
import Security

enum CieCardError: Error {
  case wrongPin(attemptsLeft: Int), pinLocked, notCie, status(UInt16), secureMessaging, invalidResponse
}

/// CIE operations over a raw APDU transport (CoreNFC is wrapped by the caller).
final class CieCard {
  private let transmit: (Data) async throws -> Data
  private var sm: (enc: [UInt8], mac: [UInt8], ssc: [UInt8])?
  /// Source of the IFD randoms; replaceable for deterministic tests.
  var random: (Int) -> [UInt8] = { count in
    var bytes = [UInt8](repeating: 0, count: count)
    precondition(SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess)
    return bytes
  }

  /// `transmit` sends a command APDU and returns response data followed by SW1 SW2.
  init(transmit: @escaping (Data) async throws -> Data) {
    self.transmit = transmit
  }

  /// NIS from EF.ID_Servizi (EF 1001): identifies the card and is readable without the PIN.
  func serviceId() async throws -> Data {
    sm = nil
    try await selectApplications()
    try await send(0x00, 0xA4, 0x02, 0x04, [0x10, 0x01])
    let r = try await send(0x00, 0xB0, 0x00, 0x00, le: 0x0C)
    guard r.sw == 0x9000 else { throw CieCardError.notCie }
    return Data(r.data)
  }

  /// Selects IAS + CIE apps, opens secure messaging (DH key exchange + DAPP device/chip authentication), verifies the 8-digit PIN (key ref 0x81).
  func open(pin: String) async throws {
    sm = nil
    try await selectApplications()

    var gpq = [[UInt8]]()
    for tag: UInt8 in [0x97, 0x98, 0x99] {
      let r = try await ok(send(0x00, 0xCB, 0x3F, 0xFF, [0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, tag, 0x00]))
      gpq.append(try find(UInt(tag), in: r))
    }
    let (g, p, q) = (gpq[0], gpq[1], gpq[2])
    let chip = try await readFile(0x1004, chunk: 0xFF)
    let iccKey = try children(of: chip, in: children(of: chip, in: 0..<1)[0].value).map { Array(chip[$0.value]) }
    guard iccKey.count >= 2 else { throw CieCardError.invalidResponse }
    let ca = try await ok(send(0x00, 0xCB, 0x3F, 0xFF, [0x4D, 0x09, 0x70, 0x07, 0xBF, 0xA0, 0x04, 0x03, 0x7F, 0x49, 0x80]))
    let (caN, caCHR, caCHA) = try (Array(find(0x81, in: ca).drop { $0 == 0 }), find(0x5F20, in: ca), find(0x5F4C, in: ca))

    // Some cards zero-pad q to the length of p (a 256-bit q in 256 bytes): drawn at full length, x would almost never be
    // below it and this loop would spin until iOS drops the idle session. Draw it over q's significant bytes instead.
    let order = Array(q.drop { $0 == 0 })
    guard !order.isEmpty else { throw CieCardError.invalidResponse }
    var x: [UInt8]
    repeat { x = random(order.count) } while !x.lexicographicallyPrecedes(order)
    let pubIFD = try modPow(g, x, p)
    try await ok(send(0x00, 0x22, 0x41, 0xA6, tlv(0x80, [0x9B]) + tlv(0x83, [0x81]) + tlv(0x91, pubIFD)))
    let pubICC = try await find(0x91, in: ok(send(0x00, 0xCB, 0x3F, 0xFF, [0x4D, 0x04, 0xA6, 0x02, 0x91, 0x00])))
    let secret = try modPow(pubICC, x, p)
    sm = (Array(sha256(secret + [0, 0, 0, 1]).prefix(16)), Array(sha256(secret + [0, 0, 0, 2]).prefix(16)), [0, 0, 0, 0, 0, 0, 0, 1])

    // DAPP (IAS-ECC 5.2.3): the IFD certificate is signed with the CA key, recoverable part per ISO 9796-2 scheme 1
    let serialIFD = bytes("2000000000000001")
    let chr = [0, 0, 0, 0] + serialIFD
    let car = Array(caCHR.dropFirst(4))
    let cert = [0x8A] + car + chr + caCHA.prefix(6) + [0x01] + bytes("2A8122F42A02040104") + Self.dappModulus + [0x00, 0x01, 0x00, 0x01]
    let split = caN.count - 34
    guard split > 0, split < cert.count else { throw CieCardError.invalidResponse }
    let certSignature = try modPow([0x6A] + cert.prefix(split) + sha256(cert) + [0xBC], Self.caPrivateExponent, caN)
    try await ok(send(0x00, 0x22, 0x81, 0xB6, tlv(0x80, [0x41]) + tlv(0x83, [0x84])))
    try await ok(send(0x00, 0x2A, 0x00, 0xAE, tlv(0x7F21, tlv(0x5F37, certSignature) + tlv(0x5F38, Array(cert[split...])) + tlv(0x42, car))))
    try await ok(send(0x00, 0x22, 0x81, 0xA4, tlv(0x83, chr)))
    let rndICC = try await ok(send(0x00, 0x84, 0x00, 0x00, le: 0x08))
    let prnd = random(Self.dappModulus.count - 34)
    let digest = sha256(prnd + pubIFD + serialIFD + rndICC + pubICC + g + p + q)
    let extAuth = try modPow([0x6A] + prnd + digest + [0xBC], Self.dappPrivateExponent, Self.dappModulus)
    try await ok(send(0x00, 0x82, 0x00, 0x00, serialIFD + extAuth))

    try await ok(send(0x00, 0x22, 0x41, 0xA4, tlv(0x84, [0x82]) + tlv(0x80, [0x9B])))
    let rndIFD = random(8)
    let intAuth = try await ok(send(0x00, 0x88, 0x00, 0x00, rndIFD))
    guard intAuth.count > 8 else { throw CieCardError.secureMessaging }
    let m = try modPow(Array(intAuth[8...]), iccKey[1], iccKey[0])
    guard m.count > 34, m.first == 0x6A, m.last == 0xBC,
          Array(m[(m.count - 33)..<(m.count - 1)]) == sha256(m[1..<(m.count - 33)] + pubICC + intAuth.prefix(8) + rndIFD + pubIFD + g + p + q)
    else { throw CieCardError.secureMessaging }
    sm?.ssc = Array(rndICC.suffix(4) + rndIFD.suffix(4))

    switch try await send(0x00, 0x20, 0x00, 0x81, Array(pin.utf8)).sw {
    case 0x9000: return
    case 0x6983, 0x63C0: throw CieCardError.pinLocked
    case let sw where sw & 0xFFF0 == 0x63C0: throw CieCardError.wrongPin(attemptsLeft: Int(sw & 0xF))
    case let sw: throw CieCardError.status(sw)
    }
  }

  /// DER authentication certificate from EF 1003, trimmed to its outer ASN.1 length.
  func certificate() async throws -> Data {
    guard sm != nil else { throw CieCardError.secureMessaging }
    return Data(try await readFile(0x1003, chunk: 0x80))
  }

  /// Card applies PKCS#1 v1.5 type-1 padding to `digestInfo`; returns the raw RSA signature.
  func sign(_ digestInfo: Data) async throws -> Data {
    guard sm != nil else { throw CieCardError.secureMessaging }
    try await ok(send(0x00, 0x22, 0x41, 0xA4, tlv(0x80, [0x02]) + tlv(0x84, [0x81])))
    return Data(try await ok(send(0x00, 0x88, 0x00, 0x00, [UInt8](digestInfo))))
  }

  private func selectApplications() async throws {
    var sw = try await send(0x00, 0xA4, 0x04, 0x0C, bytes("A0000000308000000009816001")).sw
    if sw == 0x6A82 { sw = try await send(0x00, 0xA4, 0x00, 0x00).sw }  // NXP chips have no IAS AID: select MF
    guard sw == 0x9000, try await send(0x00, 0xA4, 0x04, 0x0C, bytes("A00000000039")).sw == 0x9000 else {
      throw CieCardError.notCie
    }
  }

  /// Reads a transparent EF up to the end of its first TLV (files are zero-padded).
  private func readFile(_ id: UInt16, chunk: UInt8) async throws -> [UInt8] {
    try await ok(send(0x00, 0xA4, 0x02, 0x04, [UInt8(id >> 8), UInt8(id & 0xFF)]))
    var out = [UInt8](), le = chunk
    func end() -> Int? { (try? children(of: out, in: 0..<1))?.first?.value.upperBound }
    while end().map({ out.count < $0 }) ?? true {
      let r = try await send(0x00, 0xB0, UInt8(out.count >> 8), UInt8(out.count & 0xFF), le: le)
      if r.sw >> 8 == 0x6C { le = UInt8(r.sw & 0xFF); continue }
      guard [0x9000, 0x6282, 0x6B00].contains(r.sw) else { throw CieCardError.status(r.sw) }
      out += r.data
      guard r.sw == 0x9000, !r.data.isEmpty else { break }
      le = chunk
    }
    guard let end = end(), out.count >= end else { throw CieCardError.invalidResponse }
    return Array(out[..<end])
  }

  @discardableResult
  private func ok(_ r: (data: [UInt8], sw: UInt16)) throws -> [UInt8] {
    guard r.sw == 0x9000 else { throw CieCardError.status(r.sw) }
    return r.data
  }

  /// Sends a command with chaining, GET RESPONSE and (once established) secure messaging.
  @discardableResult
  private func send(_ cla: UInt8, _ ins: UInt8, _ p1: UInt8, _ p2: UInt8, _ data: [UInt8] = [], le: UInt8? = nil) async throws -> (data: [UInt8], sw: UInt16) {
    let size = sm == nil ? 0xFF : 0xE7
    var offset = 0
    while true {
      let chunk = Array(data[offset..<min(offset + size, data.count)])
      offset += chunk.count
      let last = offset == data.count
      let header = [last ? cla : cla | 0x10, ins, p1, p2]
      let leField: [UInt8] = last ? le.map { [$0] } ?? [] : []
      var r = try await exchange(sm == nil ? header + (chunk.isEmpty ? [] : [UInt8(chunk.count)] + chunk) + leField : wrap(header, chunk, leField))
      while r.sw >> 8 == 0x61 {
        let next = try await exchange([0x00, 0xC0, 0x00, 0x00, UInt8(r.sw & 0xFF)])
        r = (r.data + next.data, next.sw)
      }
      if sm != nil { r = try unwrap(r.data, r.sw) }
      if last || r.sw != 0x9000 { return r }
    }
  }

  private func exchange(_ apdu: [UInt8]) async throws -> (data: [UInt8], sw: UInt16) {
    let r = [UInt8](try await transmit(Data(apdu)))
    guard r.count >= 2 else { throw CieCardError.invalidResponse }
    return (Array(r.dropLast(2)), UInt16(r[r.count - 2]) << 8 | UInt16(r[r.count - 1]))
  }

  /// IAS-ECC 7.1.8: 3DES-CBC (zero IV) cryptogram, retail MAC over pad(SSC || header) || DOs.
  private func wrap(_ header: [UInt8], _ data: [UInt8], _ le: [UInt8]) throws -> [UInt8] {
    guard var s = sm else { throw CieCardError.secureMessaging }
    increment(&s.ssc)
    sm = s
    let header = [header[0] | 0x0C] + header[1...]
    var dos = [UInt8]()
    if !data.isEmpty {
      let c = try cipher(kCCEncrypt, kCCAlgorithm3DES, s.enc + s.enc.prefix(8), pad(data))
      dos += header[1] & 1 == 0 ? tlv(0x87, [0x01] + c) : tlv(0x85, c)
    }
    if !le.isEmpty { dos += tlv(0x97, le) }
    dos += try tlv(0x8E, mac(s.mac, pad(s.ssc + header) + dos))
    return header + [UInt8(dos.count)] + dos + [0x00]
  }

  private func unwrap(_ body: [UInt8], _ sw: UInt16) throws -> (data: [UInt8], sw: UInt16) {
    guard var s = sm else { throw CieCardError.secureMessaging }
    if body.isEmpty {
      guard sw != 0x9000 else { throw CieCardError.secureMessaging }
      return ([], sw)
    }
    increment(&s.ssc)
    sm = s
    var macInput = s.ssc, cc: [UInt8]?, inner: UInt16?, cryptogram: [UInt8]?
    for item in try children(of: body, in: body.indices) {
      let v = Array(body[item.value])
      switch item.tag {
      case 0x8E: cc = v; continue
      case 0x99 where v.count == 2: inner = UInt16(v[0]) << 8 | UInt16(v[1])
      case 0x87 where v.first == 0x01: cryptogram = Array(v.dropFirst())
      case 0x85: cryptogram = v
      default: throw CieCardError.secureMessaging
      }
      macInput += body[item.raw]
    }
    guard let cc, let inner, try cc == mac(s.mac, macInput) else { throw CieCardError.secureMessaging }
    guard let cryptogram else { return ([], inner) }
    let plain = try cipher(kCCDecrypt, kCCAlgorithm3DES, s.enc + s.enc.prefix(8), cryptogram)
    guard let end = plain.lastIndex(where: { $0 != 0 }), plain[end] == 0x80 else { throw CieCardError.secureMessaging }
    return (Array(plain[..<end]), inner)
  }

  private static let dappModulus = bytes(
    "BA2837AB4C6BB827577BFF4EB7B1E49CDDE0F16614D1EF24C1B75CF70FB12CD18F4D14E2814BA4877EA800E175906076B562BA535973C5D8B378051D8AFC7407"
      + "A1D919529E03C106CDA18D699AFB0D8AB4FDDD9DC719159A50DE9468F02AB103E282A50E716EC23CDA5BFC4A232B09A4B2C70745939549099B4483CBAE62D009"
      + "9674DBF6F39B7223A99D88E33F1A0CDEDEEBBDC35517ABE9880AAB240E1EA166283A274A9AD93B4B1D19F3679F3E8B5FF6A1E0ED736E84D5ABE03C59E7346B42"
      + "18755D75366CBF4136F0A26C3DC70A69ABAAF66E13A1B2FAAD052CA6EC9C51E2AED14D16E090254DC3F64EA2BD8A836BBA99DEFACBA3A613AEEDD93A9615273D")
  private static let dappPrivateExponent = bytes(
    "4716C2A38CCC7A07B415EB1A6175F2AAA0E49CEAF1BA75CBA09A684B04D8111879D3E2CCD8B94D3C5CF6C55753F0ED9587910B3C77258A01460FE84C2EDE5764"
      + "EEBE9C37FB95CD69CEAF09F4B1357C276314AB43EC5B3CEFB0403F868F688E2EC09A4973E987756F8DA7A101A2CA75A54A8C4CCF9A1B6147E4DE56423AF70B20"
      + "67179C5EEB646867863478D752C7F412DB277541575AA0619D30BCCC8D87E6170B33439A2C93F2D97E18C0A82343A6012A5BB1822808F01B5CFD85673AC0964C"
      + "5F3CFD2DAF8142359764A9ADB9E3F76DB613461C1BC913DC9AC0AB50D365F77CB93194C98AA966D89CDD555125A5E59ECF4FA3F0C3FD610CD3D056439338FD81")
  /// Private exponent matching the card's external-authentication CA public key (GET DATA 7F49).
  private static let caPrivateExponent = bytes(
    "186B31488C25DCF85D953D3630C0D073BA1C6AA24581AD254F3B6719C5D72CCA3E5CDC5A1E5316578D75954FF73B237B532C9F8DE4A2C4C911385A23E63E33E4"
      + "7EE45E66EFD49B18E02CFF87598C39109E8F86A66BC330249CE3FCAD655DCDBF98C9C5E479321AF53B517D041061880A647BBE0FF813683470E6C50094CE81D0"
      + "64E204E351BD3AE0A7947D8E91C3FD5C0A15233C349A5215A4E66E21C5D33498E71991EA24473B29F1475F6FD9BE3996E19BD474FAD1B41EA0DCD2FC16C9BFFA"
      + "071BFEC1B22415184811C1985FBFE3E7B4F44A4B3C8DFAB4D90CECFC5E608D673E6762C62CB798341271149BA688162EC7D0E3468F65A94AB4AD1AB67E37BFC1")
}

private func bytes(_ hex: String) -> [UInt8] {
  let c = Array(hex.utf8)
  return stride(from: 0, to: c.count, by: 2).map { UInt8(String(decoding: c[$0...$0 + 1], as: UTF8.self), radix: 16)! }
}

private func sha256<D: DataProtocol>(_ data: D) -> [UInt8] { Array(SHA256.hash(data: data)) }

private func pad(_ data: [UInt8]) -> [UInt8] {
  data + [0x80] + [UInt8](repeating: 0, count: 7 - data.count % 8)
}

private func increment(_ counter: inout [UInt8]) {
  for i in counter.indices.reversed() {
    counter[i] &+= 1
    if counter[i] != 0 { return }
  }
}

/// CBC with zero IV, no padding.
private func cipher(_ op: Int, _ alg: Int, _ key: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
  var out = [UInt8](repeating: 0, count: data.count)
  var moved = 0
  let (count, iv) = (data.count, [UInt8](repeating: 0, count: 8))
  guard CCCrypt(CCOperation(op), CCAlgorithm(alg), 0, key, key.count, iv, data, count, &out, count, &moved) == kCCSuccess else {
    throw CieCardError.secureMessaging
  }
  return out
}

/// ISO 9797-1 MAC algorithm 3 (retail MAC) with ISO padding.
private func mac(_ key: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
  let (k1, k2) = (Array(key[0..<8]), Array(key[8..<16]))
  let last = Array(try cipher(kCCEncrypt, kCCAlgorithmDES, k1, pad(data)).suffix(8))
  return try cipher(kCCEncrypt, kCCAlgorithmDES, k1, cipher(kCCDecrypt, kCCAlgorithmDES, k2, last))
}

/// base^exp mod modulus, computed as a raw RSA public-key operation (corecrypto accepts any exponent, even ones).
private func modPow(_ base: [UInt8], _ exp: [UInt8], _ modulus: [UInt8]) throws -> [UInt8] {
  func integer(_ v: [UInt8]) -> [UInt8] {
    let v = Array(v.drop { $0 == 0 })
    return tlv(0x02, (v.first ?? 0x80) < 0x80 ? v : [0] + v)
  }
  let (n, b) = (Array(modulus.drop { $0 == 0 }), Array(base.drop { $0 == 0 }))
  let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
  guard b.count <= n.count, let key = SecKeyCreateWithData(Data(tlv(0x30, integer(n) + integer(exp))) as CFData, attributes, nil),
        let r = SecKeyCreateEncryptedData(key, .rsaEncryptionRaw, Data(count: n.count - b.count) + b as CFData, nil)
  else { throw CieCardError.secureMessaging }
  return [UInt8](r as Data)
}

private func tlv(_ tag: UInt, _ value: [UInt8]) -> [UInt8] {
  let n = value.count
  let length: [UInt8] = n < 0x80 ? [UInt8(n)] : n < 0x100 ? [0x81, UInt8(n)] : [0x82, UInt8(n >> 8), UInt8(n & 0xFF)]
  return (tag > 0xFF ? [UInt8(tag >> 8), UInt8(tag & 0xFF)] : [UInt8(tag)]) + length + value
}

private typealias TLV = (tag: UInt, constructed: Bool, raw: Range<Int>, value: Range<Int>)

/// BER-TLV items starting within `range` of `bytes`; 00/FF bytes between items are skipped as padding.
private func children(of bytes: [UInt8], in range: Range<Int>) throws -> [TLV] {
  var items = [TLV]()
  var i = range.lowerBound
  func next() throws -> UInt8 {
    guard i < bytes.count else { throw CieCardError.invalidResponse }
    defer { i += 1 }
    return bytes[i]
  }
  while i < range.upperBound {
    let start = i, first = try next()
    if first == 0x00 || first == 0xFF { continue }
    var tag = UInt(first)
    if first & 0x1F == 0x1F {
      var b: UInt8
      repeat { b = try next(); tag = tag << 8 | UInt(b) } while b & 0x80 != 0
    }
    var length = try Int(next())
    if length > 0x80 {
      guard length <= 0x83 else { throw CieCardError.invalidResponse }
      length = try (0..<(length & 0x7F)).reduce(0) { acc, _ in try acc << 8 | Int(next()) }
    } else if length == 0x80 {
      throw CieCardError.invalidResponse
    }
    guard i + length <= bytes.count else { throw CieCardError.invalidResponse }
    items.append((tag, first & 0x20 != 0, start..<(i + length), i..<(i + length)))
    i += length
  }
  return items
}

/// Depth-first search for the value of `tag`.
private func find(_ tag: UInt, in bytes: [UInt8]) throws -> [UInt8] {
  func search(_ range: Range<Int>) throws -> [UInt8]? {
    for item in try children(of: bytes, in: range) {
      if item.tag == tag { return Array(bytes[item.value]) }
      if item.constructed, let v = try search(item.value) { return v }
    }
    return nil
  }
  guard let v = try search(bytes.indices), v.count > 0 else { throw CieCardError.invalidResponse }
  return v
}
