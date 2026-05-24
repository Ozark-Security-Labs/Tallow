#!/usr/bin/env python3
"""Generate safe synthetic archive rejection fixtures for Tallow."""
import argparse, io, tarfile, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def write_tar(name, entries):
    with tarfile.open(ROOT / name, "w") as tf:
        for kind, arcname, body, link in entries:
            info = tarfile.TarInfo(arcname)
            if kind == "file":
                data = body.encode()
                info.size = len(data)
                info.mode = 0o644
                tf.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = link
                info.mode = 0o777
                tf.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = link
                info.mode = 0o777
                tf.addfile(info)


def write_zip(name, entries):
    with zipfile.ZipFile(ROOT / name, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, body in sorted(entries.items()):
            info = zipfile.ZipInfo(arcname, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, body)


def generate():
    write_tar("tar-traversal.tar", [("file", "../evil.txt", "synthetic", "")])
    write_tar("tar-symlink-escape.tar", [("symlink", "pkg/link", "", "../../etc/passwd")])
    write_tar("tar-hardlink-escape.tar", [("hardlink", "pkg/hard", "", "../../etc/passwd")])
    write_tar("tar-oversize-marker.tar", [("file", "pkg/big.txt", "oversize marker", "")])
    write_zip("zip-slip.zip", {"../evil.py": "synthetic"})
    write_zip("wheel-zip-slip.whl", {"pkg/__init__.py": "", "../evil.py": "synthetic"})


def verify():
    required = ["tar-traversal.tar", "tar-symlink-escape.tar", "tar-hardlink-escape.tar", "tar-oversize-marker.tar", "zip-slip.zip", "wheel-zip-slip.whl"]
    for name in required:
        p = ROOT / name
        if not p.exists():
            raise SystemExit(f"missing fixture {name}")
        if p.stat().st_size > 64 * 1024:
            raise SystemExit(f"fixture too large {name}")
        data = p.read_bytes().lower()
        for forbidden in [b"malware", b"password=", b"secret", b"private key"]:
            if forbidden in data:
                raise SystemExit(f"forbidden marker {forbidden!r} in {name}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()
    generate()
    verify()
