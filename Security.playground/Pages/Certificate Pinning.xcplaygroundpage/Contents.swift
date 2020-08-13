//: [Previous](@previous)

/// Certificate Pinning
// Based on: https://infinum.com/the-capsized-eight/ssl-pinning-revisited

import Foundation
import PlaygroundSupport

// Get the reference to the cert data
guard let certificatePath = Bundle.main.path(forResource: "github", ofType: "cer") else {
    fatalError("Cannot find cert path.")
}
let certificateData = try Data(contentsOf: URL(fileURLWithPath: certificatePath))

class SessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Check the challange
        guard let trust = challenge.protectionSpace.serverTrust, SecTrustGetCertificateCount(trust) > 0 else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // Get the cerfificate from the challenge
        guard let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data
        
        // Compare the server certificate with our own stored
        guard certificateData == serverCertificateData else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

let url = URL(string: "https://github.com/gwikiera/security_playground")!
let sessionDelegate = SessionDelegate()
let urlSession = URLSession(configuration: .ephemeral,
                            delegate: sessionDelegate,
                            delegateQueue: .main)

urlSession.dataTask(with: url) { (data, response, error) in
    guard let data = data else {
        fatalError("Task failed with error: \(String(describing: error)).")
    }
    
    print("Response: \(String(describing: response))")
    print("Data: \(data)")
    
    PlaygroundPage.current.finishExecution()
}.resume()

PlaygroundPage.current.needsIndefiniteExecution = true

//: [Next](@next)
