import Foundation
import LocalAuthentication

public enum TouchIDError: Error, CustomStringConvertible {
    case notAvailable(String)
    case authFailed(String)

    public var description: String {
        switch self {
        case .notAvailable(let msg): return "Touch ID not available: \(msg)"
        case .authFailed(let msg): return msg
        }
    }
}

public protocol BiometricAuth {
    func authenticate(reason: String) throws
}

public struct SystemBiometricAuth: BiometricAuth {
    public init() {}

    public func authenticate(reason: String) throws {
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
