"""Verify the signed manifest and reconstruct an incoming release executable."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PUBLIC_KEY_B64 = "AJoLh3y/pPSuIfd55X4ddLOz+OmuMcsxEiy7o4K/mZA="
MAX_SIZE = 500 * 1024 * 1024


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    envelope = json.loads((root / "latest.json").read_text(encoding="utf-8"))
    if set(envelope) != {"payload", "signature"}:
        raise ValueError("unexpected manifest envelope fields")
    payload_bytes = base64.b64decode(envelope["payload"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    public_key = base64.b64decode(PUBLIC_KEY_B64, validate=True)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload_bytes)
    except InvalidSignature as exc:
        raise ValueError("invalid release signature") from exc
    payload = json.loads(payload_bytes)

    required = {"schema", "version", "tag", "asset", "sha256", "size", "notes"}
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("unexpected signed manifest fields")
    if payload["schema"] != 1:
        raise ValueError("unsupported manifest schema")
    if not re.fullmatch(r"\d+\.\d+\.\d+", payload["version"]):
        raise ValueError("invalid version")
    expected_tag = f"icon-tools-{payload['version']}"
    if payload["tag"] != expected_tag:
        raise ValueError("tag/version mismatch")
    if payload["asset"] != f"{expected_tag}/IconTools.exe":
        raise ValueError("unexpected asset path")
    if not re.fullmatch(r"[0-9a-f]{64}", payload["sha256"]):
        raise ValueError("invalid digest")
    if not isinstance(payload["size"], int) or not 0 < payload["size"] <= MAX_SIZE:
        raise ValueError("invalid file size")

    parts = sorted(root.glob("IconTools.exe.part*"))
    if not parts:
        raise ValueError("no executable parts found")
    output_path = root / "IconTools.exe"
    digest = hashlib.sha256()
    size = 0
    with output_path.open("wb") as output:
        for part in parts:
            with part.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    size += len(chunk)
                    if size > payload["size"]:
                        raise ValueError("executable exceeds signed size")
                    digest.update(chunk)
                    output.write(chunk)
    if size != payload["size"] or digest.hexdigest() != payload["sha256"]:
        output_path.unlink(missing_ok=True)
        raise ValueError("reconstructed executable does not match signed manifest")
    print(expected_tag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
