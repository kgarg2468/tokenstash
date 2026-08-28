#!/usr/bin/env python3
"""Repack the release tarballs into platform wheels so `pipx install tokenstash` /
`uv tool install tokenstash` work. No Python code ships: the wheel carries only the binary
under `tokenstash-<version>.data/scripts/`, which installers place on PATH with the exec
bit. macOS wheels are tagged per arch; Linux wheels carry manylinux + musllinux tags (static).

    scripts/pypi-wheels.py <version> <dir-with-tokenstash-*.tar.gz> <out-dir>
"""
import base64, hashlib, io, os, sys, tarfile, zipfile

# Linux binaries are static, so they need nothing from the platform: tag them for glibc
# (manylinux_2_17 is the floor old pips accept) AND musl in one compressed tag set, the way
# ruff/uv ship. pip on a glibc system refuses a musllinux-only wheel even though the binary runs.
PLATFORMS = {
    "linux-x64": "manylinux_2_17_x86_64.manylinux2014_x86_64.musllinux_1_1_x86_64",
    "linux-arm64": "manylinux_2_17_aarch64.manylinux2014_aarch64.musllinux_1_1_aarch64",
    "darwin-x64": "macosx_10_12_x86_64",
    "darwin-arm64": "macosx_11_0_arm64",
}
NAME = "tokenstash"

def metadata(version, readme):
    return (
        "Metadata-Version: 2.1\n"
        f"Name: {NAME}\n"
        f"Version: {version}\n"
        "Summary: Your agent asks you for a key once. Never again - in any project, in any agent.\n"
        "Home-page: https://github.com/kgarg2468/tokenstash\n"
        "Author: Krish Garg\n"
        "License: MIT\n"
        "Project-URL: Repository, https://github.com/kgarg2468/tokenstash\n"
        "Project-URL: Changelog, https://github.com/kgarg2468/tokenstash/blob/main/CHANGELOG.md\n"
        "Classifier: License :: OSI Approved :: MIT License\n"
        "Classifier: Environment :: Console\n"
        "Classifier: Topic :: Security\n"
        "Requires-Python: >=3.8\n"
        "Description-Content-Type: text/markdown\n\n" + readme
    )

def build(version, src, out, readme, license_text):
    os.makedirs(out, exist_ok=True)
    for name, tag in PLATFORMS.items():
        tar = os.path.join(src, f"tokenstash-{name}.tar.gz")
        with tarfile.open(tar) as t:
            binary = t.extractfile("tokenstash").read()
        distinfo = f"{NAME}-{version}.dist-info"
        data = f"{NAME}-{version}.data"
        files = [
            (f"{data}/scripts/tokenstash", binary, 0o755),
            (f"{distinfo}/METADATA", metadata(version, readme).encode(), 0o644),
            (f"{distinfo}/WHEEL", (
                "Wheel-Version: 1.0\nGenerator: tokenstash-release\nRoot-Is-Purelib: false\n"
                + "".join(f"Tag: py3-none-{t}\n" for t in tag.split("."))).encode(), 0o644),
            (f"{distinfo}/LICENSE", license_text.encode(), 0o644),
            (f"{distinfo}/top_level.txt", b"", 0o644),
        ]
        record = []
        path = os.path.join(out, f"{NAME}-{version}-py3-none-{tag}.whl")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            for arc, blob, mode in files:
                info = zipfile.ZipInfo(arc, date_time=(1980, 1, 1, 0, 0, 0))
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, blob)
                digest = base64.urlsafe_b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode()
                record.append(f"{arc},sha256={digest},{len(blob)}")
            record.append(f"{distinfo}/RECORD,,")
            info = zipfile.ZipInfo(f"{distinfo}/RECORD", date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = (0o100000 | 0o644) << 16
            z.writestr(info, "\n".join(record) + "\n")
        print(path)

if __name__ == "__main__":
    version, src, out = sys.argv[1:4]
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
    build(version, src, out, open(os.path.join(root, "README.md")).read(), open(os.path.join(root, "LICENSE")).read())
