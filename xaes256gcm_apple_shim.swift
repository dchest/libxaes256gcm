// 
// Copyright (c) 2026 Dmitry Chestnykh <dmitry@codingrobots.com>
// 
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
// 

import Foundation
import CryptoKit

@_cdecl("xaes256gcm_internal_gcm_seal")
func aes256gcm_seal(
    _ c: UnsafeMutableRawPointer,
    _ key: UnsafePointer<UInt8>,
    _ nonce: UnsafePointer<UInt8>,
    _ plaintext: UnsafePointer<UInt8>?,
    _ plaintext_len: UInt,
    _ aad: UnsafePointer<UInt8>?,
    _ aad_len: UInt,
    _ ciphertext: UnsafeMutablePointer<UInt8>?,
    _ ciphertext_max_len: UInt
) -> Int {
    // C funcs accept size_t, we want Int in Swift, safely.
    guard let ptLen = Int(exactly: plaintext_len),
          let aadLen = Int(exactly: aad_len),
          let ctMaxLen = Int(exactly: ciphertext_max_len),
          ctMaxLen >= 16, ctMaxLen - 16 >= ptLen,
          let gcmNonce = try? AES.GCM.Nonce(data: UnsafeBufferPointer(start: nonce, count: 12)),
          let ciphertext = ciphertext
    else { return -1 }

    let symKey = SymmetricKey(data: UnsafeBufferPointer(start: key, count: 32))
    let pt = ptLen > 0 ? Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: plaintext!), count: ptLen, deallocator: .none) : Data()
    let ad = aadLen > 0 ? Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: aad!), count: aadLen, deallocator: .none) : Data()

    guard let sealedBox = try? AES.GCM.seal(pt, using: symKey, nonce: gcmNonce, authenticating: ad)
    else { return -1 }

    sealedBox.ciphertext.withUnsafeBytes { ct in
        UnsafeMutableRawPointer(ciphertext).copyMemory(from: ct.baseAddress!, byteCount: ct.count)
    }
    sealedBox.tag.withUnsafeBytes { tag in
        UnsafeMutableRawPointer(ciphertext + ptLen).copyMemory(from: tag.baseAddress!, byteCount: tag.count)
    }
    return 0
}

@_cdecl("xaes256gcm_internal_gcm_open")
func aes256gcm_open(
    _ c: UnsafeMutableRawPointer,
    _ key: UnsafePointer<UInt8>,
    _ nonce: UnsafePointer<UInt8>,
    _ ciphertext: UnsafePointer<UInt8>?,
    _ ciphertext_len: UInt,
    _ aad: UnsafePointer<UInt8>?,
    _ aad_len: UInt,
    _ plaintext: UnsafeMutablePointer<UInt8>?,
    _ plaintext_max_len: UInt
) -> Int {
    // C funcs accept size_t, we want Int in Swift, safely.
    guard let ctLen = Int(exactly: ciphertext_len),
          let aadLen = Int(exactly: aad_len),
          let ptMaxLen = Int(exactly: plaintext_max_len),
          ctLen >= 16, ptMaxLen >= ctLen - 16,
          let gcmNonce = try? AES.GCM.Nonce(data: UnsafeBufferPointer(start: nonce, count: 12)),
          let ciphertext = ciphertext
    else { return -1 }

    let ctLenNoTag = ctLen - 16
    let symKey = SymmetricKey(data: UnsafeBufferPointer(start: key, count: 32))
    let ct = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: ciphertext), count: ctLenNoTag, deallocator: .none)
    let tag = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: ciphertext.advanced(by: ctLenNoTag)), count: 16, deallocator: .none)
    let ad = aadLen > 0 ? Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: aad!), count: aadLen, deallocator: .none) : Data()

    guard let sealedBox = try? AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ct, tag: tag),
          let pt = try? AES.GCM.open(sealedBox, using: symKey, authenticating: ad)
    else { return -1 }

    if ctLenNoTag > 0 {
        pt.withUnsafeBytes { src in
            UnsafeMutableRawPointer(plaintext!).copyMemory(from: src.baseAddress!, byteCount: pt.count)
        }
    }
    return 0
}
