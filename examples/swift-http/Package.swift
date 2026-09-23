// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "StogasHTTPExample",
    platforms: [.macOS(.v13)],
    dependencies: [.package(path: "../../bindings/swift")],
    targets: [.executableTarget(
        name: "StogasHTTPExample",
        dependencies: [.product(name: "StogasVerifier", package: "swift")],
        path: ".",
        sources: ["main.swift"]
    )]
)
