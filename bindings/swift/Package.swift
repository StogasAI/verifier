// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "StogasVerifier",
    platforms: [.macOS(.v13)],
    products: [.library(name: "StogasVerifier", targets: ["StogasVerifier"])],
    targets: [
        .binaryTarget(name: "CStogas", path: "CStogas.artifactbundle"),
        .target(name: "StogasVerifier", dependencies: ["CStogas"], linkerSettings: [
            .linkedLibrary("dl", .when(platforms: [.linux])),
            .linkedLibrary("pthread", .when(platforms: [.linux])),
            .linkedLibrary("m", .when(platforms: [.linux])),
            .linkedFramework("Security", .when(platforms: [.macOS])),
            .linkedFramework("CoreFoundation", .when(platforms: [.macOS])),
        ]),
        .testTarget(name: "StogasVerifierTests", dependencies: ["StogasVerifier"]),
    ]
)
