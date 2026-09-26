#!/usr/bin/env python3
"""Require the release tag and all published package versions to agree."""

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path(__file__).resolve().parents[1]
version = sys.argv[1]
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?", version):
    raise SystemExit("Invalid release version")
for name in ["package.json", "packages/offline-sigstore/package.json"]:
    assert json.loads((root / name).read_text())["version"] == version, name
assert re.search(r'^version = "([^"]+)"', (root / "Cargo.toml").read_text(), re.M)[1] == version
assert not re.search(r'^version = ', (root / "bindings/python/Cargo.toml").read_text(), re.M)
for name in ["bindings/java/pom.xml", "examples/java-openai/pom.xml"]:
    pom = ET.parse(root / name)
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    path = "m:version" if name.startswith("bindings") else "m:dependencies/m:dependency[m:groupId='ai.stogas']/m:version"
    assert pom.findtext(path, namespaces=namespace) == version, name
for name in ["bindings/dotnet/Stogas.Verifier/Stogas.Verifier.csproj", "bindings/dotnet/tests/Consumer.csproj"]:
    project = ET.parse(root / name)
    actual = project.findtext("PropertyGroup/Version") if "Stogas.Verifier/" in name else project.find("ItemGroup/PackageReference[@Include='Stogas.Verifier']").get("Version")
    assert actual == version, name
gem = re.search(r"s.version = '([^']+)'", (root / "bindings/ruby/stogas-verifier.gemspec").read_text())[1]
assert gem == version.replace("-", "."), "Ruby gem"
