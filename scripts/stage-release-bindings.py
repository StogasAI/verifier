#!/usr/bin/env python3
"""Stage the exact native release archives into the Java, NuGet and Swift packages."""

import argparse
import importlib.util
import json
import tarfile
import tempfile
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("native", Path(__file__).with_name("stage-native-bindings.py"))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--artifacts", type=Path, required=True)
args = parser.parse_args()
version = json.loads((root / "package.json").read_text())["version"]
for platform in native.PLATFORMS:
    name = f"stogas-verifier-v{version}-{platform}"
    with tempfile.TemporaryDirectory(prefix="stogas-native-") as directory:
        destination = Path(directory)
        if platform.startswith("windows"):
            with zipfile.ZipFile(args.artifacts / f"{name}.zip") as archive:
                library = "stogas_verifier_ffi.dll"
                (destination / library).write_bytes(archive.read(f"{name}/{library}"))
        else:
            extension = "dylib" if platform.startswith("darwin") else "so"
            with tarfile.open(args.artifacts / f"{name}.tar.gz") as archive:
                for library in ["libstogas_verifier_ffi.a", f"libstogas_verifier_ffi.{extension}"]:
                    member = archive.getmember(f"{name}/{library}")
                    if not member.isfile():
                        raise ValueError(f"Expected a regular library: {member.name}")
                    with archive.extractfile(member) as source, (destination / library).open("wb") as output:
                        native.shutil.copyfileobj(source, output)
        native.stage(platform, destination, root / "bindings", version)
