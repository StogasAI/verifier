#!/usr/bin/env python3
"""Stage one built C ABI library into the native language packages."""

import argparse
import json
import shutil
from pathlib import Path


# Rust release archive name -> (.NET RID, JNA resource prefix, Swift triple).
PLATFORMS = {
    "linux-amd64": ("linux-x64", "linux-x86-64", "x86_64-unknown-linux-gnu"),
    "linux-arm64": ("linux-arm64", "linux-aarch64", "aarch64-unknown-linux-gnu"),
    "darwin-amd64": ("osx-x64", "darwin-x86-64", "x86_64-apple-macosx"),
    "darwin-arm64": ("osx-arm64", "darwin-aarch64", "arm64-apple-macosx"),
    "windows-amd64": ("win-x64", "win32-x86-64", None),
}


def copy(source, destination):
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"Missing regular native artifact: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def stage(platform, native, bindings, version):
    rid, jna, swift = PLATFORMS[platform]
    extension = "dll" if platform.startswith("windows") else "dylib" if platform.startswith("darwin") else "so"
    name = ("" if extension == "dll" else "lib") + "stogas_verifier_ffi." + extension
    copy(native / name, bindings / "dotnet/Stogas.Verifier/runtimes" / rid / "native" / name)
    copy(native / name, bindings / "java/src/main/resources" / jna / name)
    copy(native / name, bindings / "ruby/lib/stogas/native" / name)

    if swift:
        bundle = bindings / "swift/CStogas.artifactbundle"
        static = "libstogas_verifier_ffi.a"
        copy(native / static, bundle / platform / static)
        copy(Path(__file__).resolve().parents[1] / "include/stogas_verifier.h", bundle / "include/stogas_verifier.h")
        (bundle / "include/module.modulemap").write_text('module CStogas { header "stogas_verifier.h" export * }\n')
        manifest = bundle / "info.json"
        artifact = {"type": "staticLibrary", "version": version, "variants": []}
        if manifest.exists():
            artifact = json.loads(manifest.read_text())["artifacts"]["CStogas"]
            if artifact["version"] != version:
                raise ValueError("Cannot combine native libraries from different releases")
        path = f"{platform}/{static}"
        variants = [v for v in artifact["variants"] if v["path"] != path]
        variants.append({
            "path": path,
            "supportedTriples": [swift],
            "staticLibraryMetadata": {"headerPaths": ["include"], "moduleMapPath": "include/module.modulemap"},
        })
        artifact["variants"] = sorted(variants, key=lambda v: v["path"])
        manifest.write_text(json.dumps({"schemaVersion": "1.0", "artifacts": {"CStogas": artifact}}, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    parser.add_argument("--native-dir", required=True, type=Path)
    parser.add_argument("--bindings-dir", type=Path, default=Path(__file__).resolve().parents[1] / "bindings")
    parser.add_argument("--version", default=json.loads((Path(__file__).resolve().parents[1] / "package.json").read_text())["version"])
    arguments = parser.parse_args()
    stage(arguments.platform, arguments.native_dir, arguments.bindings_dir, arguments.version)
