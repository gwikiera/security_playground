//: [Previous](@previous)

/// Asymmetric Encryption
// Based on: https://medium.com/flawless-app-stories/ios-security-tutorial-part-1-6571172d912

import Foundation
import Security
import XCTest

// Defining keys params and attributes
let privateKeyTag = "com.gwikiera.security".data(using: .utf8)!
let privateKeyParams: [String: Any] = [kSecAttrCanDecrypt as String: true,
                                       kSecAttrIsPermanent as String: false,
                                       kSecAttrApplicationTag as String: privateKeyTag]

let attributes = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                  kSecAttrKeySizeInBits as String: 256,
                  kSecPrivateKeyAttrs as String: privateKeyParams] as CFDictionary

// Variables to store both the public and private keys
var publicKeySec, privateKeySec: SecKey?

// Generating both the public and private keys via the SecGeneratePair APIs
SecKeyGeneratePair(attributes, &publicKeySec, &privateKeySec)

// Function to encrypt `String` using public `SecKey`
func encrypt(message: String,
             using key: SecKey,
             encoding: String.Encoding = .utf8,
             algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM) -> Data {
    guard let messageData = message.data(using: encoding) else {
        fatalError("Bad message to encrypt")
    }
    
    var error: Unmanaged<CFError>?
    guard let encryptData = SecKeyCreateEncryptedData(key,
                                                      algorithm,
                                                      messageData as CFData,
                                                      &error) else {
                                                        fatalError("Encryption Error: \(String(describing: error?.takeRetainedValue()))")
    }
    
    return encryptData as Data
}

// Function to decrypt `Data` using private `SecKey`
func decrypt(data: Data,
             using key: SecKey,
             encoding: String.Encoding = .utf8,
             algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM) -> String {
    var error: Unmanaged<CFError>?
    guard let decryptMessageData = SecKeyCreateDecryptedData(key, algorithm, data as CFData, &error) else {
        fatalError("Decryption Error: \(String(describing: error?.takeRetainedValue()))")
    }
    
    guard let decryptMessage = String(data: decryptMessageData as Data, encoding: .utf8) else {
        fatalError("Encoding Error")
    }
    return decryptMessage
}

// Test the functions
guard let publicKey = publicKeySec, let privateKey = privateKeySec else {
    fatalError("Keys Generation Error")
}

let message = UUID().uuidString
let encryptedData = encrypt(message: message, using: publicKey)
let decryptedMessage = decrypt(data: encryptedData, using: privateKey)

XCTAssertEqual(message, decryptedMessage)

//: [Next](@next)
