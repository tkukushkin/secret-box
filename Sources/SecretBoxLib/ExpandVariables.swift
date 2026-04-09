public func expandVariables(in arguments: [String], with values: [String: String]) -> [String] {
    arguments.map { arg in
        var result = arg
        for (varName, value) in values {
            result = result.replacingOccurrences(of: "$(\(varName))", with: value)
        }
        return result
    }
}
