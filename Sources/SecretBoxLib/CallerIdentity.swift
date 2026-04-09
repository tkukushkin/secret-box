import Foundation
import Security

func getPathForPid(_ pid: pid_t) -> String? {
    let pathbuf = UnsafeMutablePointer<CChar>.allocate(capacity: Int(4096))
    defer { pathbuf.deallocate() }
    let ret = proc_pidpath(pid, pathbuf, UInt32(4096))
    guard ret > 0 else { return nil }
    return String(cString: pathbuf)
}

func getParentPid(of pid: pid_t) -> pid_t {
    var info = kinfo_proc()
    var length = MemoryLayout<kinfo_proc>.size
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
    guard sysctl(&mib, 4, &info, &length, nil, 0) == 0, length > 0 else { return 0 }
    return info.kp_eproc.e_ppid
}

func extractAppBundle(from path: String) -> String? {
    if let range = path.range(of: ".app/") {
        return String(path[..<range.lowerBound]) + ".app"
    }
    if path.hasSuffix(".app") {
        return path
    }
    return nil
}

/// Walk up the process tree to find the responsible .app bundle.
func findResponsibleAppPath() -> String? {
    var pid = getppid()

    while pid > 1 {
        if let path = getPathForPid(pid), let bundle = extractAppBundle(from: path) {
            return bundle
        }
        pid = getParentPid(of: pid)
    }

    // Fallback: immediate parent's path
    return getPathForPid(getppid())
}

func getSigningIdentity(for path: String) -> String? {
    let url = URL(fileURLWithPath: path)
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
          let code = staticCode else { return nil }

    var cfInfo: CFDictionary?
    guard SecCodeCopySigningInformation(code, [], &cfInfo) == errSecSuccess,
          let info = cfInfo as? [String: Any] else { return nil }

    let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
    let signingID = info[kSecCodeInfoIdentifier as String] as? String

    if let teamID, let signingID {
        return "signed:\(teamID):\(signingID)"
    }
    if let signingID {
        return "signed::\(signingID)"
    }
    return nil
}

public struct CallerIdentity {
    public let id: String
    public let displayName: String

    public init(id: String, displayName: String) {
        self.id = id
        self.displayName = displayName
    }

    public static func current() -> CallerIdentity {
        let appPath = findResponsibleAppPath()

        let displayName: String
        if let appPath, let bundle = extractAppBundle(from: appPath) {
            displayName = (bundle as NSString).lastPathComponent.replacingOccurrences(of: ".app", with: "")
        } else if let appPath {
            displayName = (appPath as NSString).lastPathComponent
        } else {
            displayName = "Unknown app"
        }

        let callerID: String
        if let appPath {
            if let bundle = extractAppBundle(from: appPath), let sigID = getSigningIdentity(for: bundle) {
                callerID = sigID
            } else if let sigID = getSigningIdentity(for: appPath) {
                callerID = sigID
            } else {
                callerID = "path:\(sha256Hex(appPath))"
            }
        } else {
            callerID = "unknown"
        }

        return CallerIdentity(id: callerID, displayName: displayName)
    }
}
