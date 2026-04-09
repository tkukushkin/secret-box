// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "secret-box",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
        .package(url: "https://github.com/stephencelis/SQLite.swift.git", from: "0.16.0"),
    ],
    targets: [
        .target(
            name: "SecretBoxLib",
            dependencies: [
                .product(name: "SQLite", package: "SQLite.swift"),
            ],
            path: "Sources/SecretBoxLib",
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security"),
            ]
        ),
        .executableTarget(
            name: "secret-box",
            dependencies: [
                "SecretBoxLib",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/SecretBox"
        ),
        .testTarget(
            name: "SecretBoxTests",
            dependencies: [
                "SecretBoxLib",
                .product(name: "SQLite", package: "SQLite.swift"),
            ],
            path: "Tests/SecretBoxTests"
        ),
    ]
)
