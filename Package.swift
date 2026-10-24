// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ScamShield",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ScamShieldCore", targets: ["ScamShieldCore"]),
        .executable(name: "ScamShield", targets: ["ScamShield"]),
        .executable(name: "scamshieldctl", targets: ["scamshieldctl"]),
    ],
    targets: [
        .target(name: "ScamShieldCore"),
        .executableTarget(name: "ScamShield", dependencies: ["ScamShieldCore"]),
        .executableTarget(name: "scamshieldctl", dependencies: ["ScamShieldCore"]),
        .testTarget(name: "ScamShieldCoreTests", dependencies: ["ScamShieldCore"]),
    ]
)
