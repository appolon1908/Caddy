#!/usr/bin/env python3
"""Write throwaway certificate material for the private mTLS listeners.

Caddy's provisioning validation loads every configured certificate and trust
pool, so CI and tests need files at the paths the private sites reference.
These are disposable self-signed test certificates generated per run; real
certificates and keys never belong in this repository.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

MIDDLEWARE_FILES = ("server", "staging-server")


def _self_signed(openssl: str, directory: Path, stem: str, subject: str) -> None:
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", f"/CN={subject}", "-addext", f"subjectAltName=DNS:{subject}",
         "-keyout", str(directory / f"{stem}.key"), "-out", str(directory / f"{stem}.crt")],
        check=True, capture_output=True,
    )


def generate(root: Path) -> dict[str, Path]:
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("SYNTHETIC_PKI_ERROR=openssl_unavailable")
    middleware = root / "middleware"
    klyrow = root / "klyrow"
    middleware.mkdir(parents=True, exist_ok=True)
    klyrow.mkdir(parents=True, exist_ok=True)
    _self_signed(openssl, middleware, "server", "middleware.internal.codestra.agency")
    _self_signed(openssl, middleware, "staging-server", "middleware-staging.internal.codestra.agency")
    _self_signed(openssl, middleware, "client-ca", "TEST_SYN middleware client CA")
    _self_signed(openssl, klyrow, "tls", "middleware-email-events.internal.codestra.agency")
    (klyrow / "tls.crt").rename(klyrow / "tls-fullchain.crt")
    _self_signed(openssl, klyrow, "klyrow-client", "TEST_SYN klyrow client")
    return {"CADDY_MIDDLEWARE_PKI_DIR": middleware, "CADDY_KLYROW_PKI_DIR": klyrow}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    for name, path in generate(args.directory).items():
        print(f"{name}={path}")


if __name__ == "__main__":
    main()
