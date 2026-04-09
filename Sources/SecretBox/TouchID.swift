import Foundation
import LocalAuthentication

enum TouchIDError: Error, CustomStringConvertible {
    case notAvailable(String)
    case authFailed(String)

    var description: String {
        switch self {
        case .notAvailable(let msg): return "Touch ID not available: \(msg)"
        case .authFailed(let msg): return msg
        }
    }
}

enum TouchID {
    /// Authenticate via Touch ID. Blocks until the user responds.
    static func authenticate(reason: String) throws {
        let context = LAContext()

        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw TouchIDError.notAvailable(error?.localizedDescription ?? "Unknown error")
        }

        let semaphore = DispatchSemaphore(value: 0)
        var authError: Error?

        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            if !success {
                authError = TouchIDError.authFailed(error?.localizedDescription ?? "Authentication failed")
            }
            semaphore.signal()
        }

        semaphore.wait()

        if let authError {
            throw authError
        }
    }
}
