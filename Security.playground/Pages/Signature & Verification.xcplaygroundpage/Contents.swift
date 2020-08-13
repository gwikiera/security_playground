//: [Previous](@previous)

/// Signature & Verification
// Based on: https://medium.com/flawless-app-stories/ios-security-tutorial-part-2-c481036170ca

import Foundation
import Security
import XCTest

// Creating the Access Control Object
var error: Unmanaged<CFError>?
guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                   kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                   [.privateKeyUsage, .biometryAny],
                                                   &error) else {
                                                    fatalError("Access Control Creation Error: \(String(describing: error?.takeRetainedValue()))")
}

let secEnclaveTag = "com.gwikiera.security".data(using: .utf8)!
let privateKeyParams: [String: AnyObject] = [kSecAttrIsPermanent as String: false as AnyObject,
                                             kSecAttrApplicationTag as String: secEnclaveTag as AnyObject,
                                             kSecAttrAccessControl as String: access]

let attributes = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                  kSecAttrKeySizeInBits as String: 256,
                  kSecPrivateKeyAttrs as String: privateKeyParams] as CFDictionary

// Creating public and private keys
guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    fatalError("Private key generation error: \(String(describing: error?.takeRetainedValue()))")
}
guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
    fatalError("Public key generation error")
}

// Testing solution
let message = UUID().uuidString
guard let messageData = message.data(using: String.Encoding.utf8) else {
    fatalError("Invalid message to sign.")
}

// Creating signature data
guard let signedData = SecKeyCreateSignature(privateKey,
                                             SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
                                             messageData as CFData,
                                             &error) else {
                                                fatalError("Signing Error: \(String(describing: error?.takeRetainedValue()))")
}
let signedString = (signedData as Data).base64EncodedString()
print("Signed String:", signedString)

// Verifying the signature
let verify = SecKeyVerifySignature(
    publicKey,
    SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
    messageData as CFData,
    signedData as CFData,
    nil)
XCTAssertTrue(verify)

//: [Next](@next)
