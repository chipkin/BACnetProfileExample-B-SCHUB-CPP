#!/usr/bin/env python3
"""Write a CycloneDX software bill of materials (SBOM) for one build.

Lists what the executable is made of: this example, the CAS BACnet Stack, and
every library vcpkg built for it (OpenSSL, libwebsockets and their own
dependencies), with versions and licences. CI runs it after each build and
ships the result with the release (issue #32):

    python tools/make-sbom.py --build-dir build --out sbom.cdx.json

It reads the example's version from main.cpp, the stack's from its git
submodule, and the libraries from vcpkg's install record
(build/vcpkg_installed/vcpkg/status). Only the Python standard library.
"""
import argparse
import datetime
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# vcpkg's own SPDX files say NOASSERTION for these ports, so the licences are
# stated here (checked against each project's LICENSE file).
LICENCES = {
    "openssl": "Apache-2.0",
    "libwebsockets": "MIT",
    "libuv": "MIT",
    "zlib": "Zlib",
    "pthreads": "Apache-2.0",
}
HOMEPAGES = {
    "openssl": "https://www.openssl.org/",
    "libwebsockets": "https://libwebsockets.org/",
    "libuv": "https://libuv.org/",
    "zlib": "https://zlib.net/",
    "pthreads": "https://sourceforge.net/projects/pthreads4w/",
}


def app_version():
    text = (ROOT / "main.cpp").read_text(encoding="utf-8")
    return re.search(r'APP_VERSION = "([0-9.]+)"', text).group(1)


def stack_info():
    stack = ROOT / "submodules" / "cas-bacnet-stack"
    try:
        commit = subprocess.run(["git", "-C", str(stack), "rev-parse", "HEAD"], capture_output=True,
                                text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = ""
    version = ""
    header = stack / "source" / "version.h"
    if header.exists():
        # The version the stack reports at run time (BACnetStack_GetAPI*Version,
        # printed by --version); the build number is CI-specific, so it is left out.
        text = header.read_text(encoding="utf-8", errors="replace")
        parts = [re.search(rf"CAS_BACNET_STACK_VERSION_{p}\s*=\s*(\d+)", text) for p in ("MAJOR", "MINOR", "PATCH")]
        if all(parts):
            version = ".".join(m.group(1) for m in parts)
    return version, commit


def vcpkg_packages(build_dir):
    """(name, version, triplet) for every library vcpkg installed for the target (not host tools)."""
    status = build_dir / "vcpkg_installed" / "vcpkg" / "status"
    packages, current = [], {}
    for line in status.read_text(encoding="utf-8").splitlines() + [""]:
        if not line.strip():
            if current.get("Package") and "install ok installed" in current.get("Status", "") \
                    and not current.get("Feature"):
                packages.append(current)
            current = {}
            continue
        key, _, value = line.partition(":")
        current[key.strip()] = value.strip()
    result = {}
    for p in packages:
        name = p["Package"]
        if name.startswith("vcpkg-"):
            continue  # build helpers, not linked into the executable
        version = p.get("Version", "")
        if p.get("Port-Version") and p["Port-Version"] != "0":
            version += "#" + p["Port-Version"]
        result[name] = (version, p.get("Architecture", ""))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", default=str(ROOT / "build"))
    parser.add_argument("--stack-version", default="", help="override the CAS BACnet Stack version")
    parser.add_argument("--out", default="sbom.cdx.json")
    args = parser.parse_args()

    version = app_version()
    stack_version, stack_commit = stack_info()
    stack_version = args.stack_version or stack_version

    components = [{
        "type": "library",
        "bom-ref": "cas-bacnet-stack",
        "supplier": {"name": "Chipkin Automation Systems"},
        "name": "CAS BACnet Stack",
        "version": stack_version or stack_commit[:12],
        "licenses": [{"license": {"name": "Commercial - Chipkin Automation Systems"}}],
        "externalReferences": [{"type": "website", "url": "https://store.chipkin.com/services/stacks/bacnet-stack"}],
        "properties": [{"name": "git-commit", "value": stack_commit}] if stack_commit else [],
    }]
    for name, (pkg_version, triplet) in sorted(vcpkg_packages(Path(args.build_dir)).items()):
        component = {
            "type": "library",
            "bom-ref": f"vcpkg:{name}",
            "name": name,
            "version": pkg_version,
            "purl": f"pkg:generic/{name}@{pkg_version.split('#')[0]}",
            "properties": [{"name": "vcpkg-triplet", "value": triplet}],
        }
        if name in LICENCES:
            component["licenses"] = [{"license": {"id": LICENCES[name]}}]
        if name in HOMEPAGES:
            component["externalReferences"] = [{"type": "website", "url": HOMEPAGES[name]}]
        components.append(component)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"name": "tools/make-sbom.py"}],
            "component": {
                "type": "application",
                "bom-ref": "bacnet-example-b-schub",
                "name": "BACnetExampleBSCHUB",
                "version": version,
                "licenses": [{"license": {"id": "CC0-1.0"}}],
                "externalReferences": [{"type": "vcs",
                                        "url": "https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP"}],
            },
        },
        "components": components,
        "dependencies": [{"ref": "bacnet-example-b-schub", "dependsOn": [c["bom-ref"] for c in components]}],
    }
    Path(args.out).write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}: {len(components)} components")
    for c in components:
        print(f"  {c['name']} {c['version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
