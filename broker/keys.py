"""Signing-key management: kid-named PEM pairs with hot reload plus JWKS.

On-disk layout inside the owner-placed, mode-600 key directory::

    <kid>.private.pem    RS256 private key, minted into tokens as `kid`
    <kid>.public.pem     matching public key, published via JWKS

Multiple kids may be present during rotation overlap; every loaded kid
verifies, while minting always uses the newest private key by mtime.
Refresh is a cheap mtime poll performed on each signing/verify call
(default poll interval only bounds negative caching, not correctness).

Legacy fallback: a directory without kid-named pairs but containing
`private.pem` / `public.pem` is loaded as kid "legacy".
"""
from __future__ import annotations

import base64
import os
import threading
import time
from pathlib import Path

from jwt.algorithms import RSAAlgorithm

LEGACY_KID = "legacy"
POLL_SECONDS_DEFAULT = 15


def discover_key_dir(key_dir: str | Path) -> dict[str, dict[str, Path]]:
    """Map kid -> {"private": path, "public": path} for complete pairs."""
    found: dict[str, dict[str, Path]] = {}
    base = Path(key_dir)
    if not base.is_dir():
        return found
    for priv in sorted(base.glob("*.private.pem")):
        kid = priv.name[: -len(".private.pem")]
        pub = base / f"{kid}.public.pem"
        if pub.is_file():
            found[kid] = {"private": priv, "public": pub}
    return found


def _public_to_jwk(public_pem: str, kid: str) -> dict:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(public_pem.encode())
    raw = RSAAlgorithm(RSAAlgorithm.SHA256).to_jwk(key)
    import json as _json

    jwk = _json.loads(raw)
    jwk["kid"] = kid
    jwk["use"] = "sig"
    return jwk


class KeyStore:
    """Hot-reloading multi-kid RSA key set."""

    def __init__(self, key_dir: str | Path, poll_seconds: int = POLL_SECONDS_DEFAULT):
        self.key_dir = Path(key_dir)
        self.poll_seconds = poll_seconds
        self._lock = threading.Lock()
        self._private: dict[str, str] = {}
        self._public: dict[str, str] = {}
        self._current_kid: str | None = None
        self._snapshot: list[tuple[str, float, float]] = []
        self._last_check = 0.0
        self.refresh(force=True)

    def _take_snapshot(self) -> list[tuple[str, float, float]]:
        pairs = discover_key_dir(self.key_dir)
        snap = []
        for kid in sorted(pairs):
            try:
                snap.append(
                    (
                        kid,
                        pairs[kid]["private"].stat().st_mtime,
                        pairs[kid]["public"].stat().st_mtime,
                    )
                )
            except OSError:
                continue
        # Legacy single-pair fallback.
        if not snap:
            priv = self.key_dir / "private.pem"
            pub = self.key_dir / "public.pem"
            if priv.is_file() and pub.is_file():
                try:
                    snap.append((LEGACY_KID, priv.stat().st_mtime, pub.stat().st_mtime))
                except OSError:
                    pass
        return snap

    def _load_snapshot(self, snap: list[tuple[str, float, float]]) -> None:
        pairs = discover_key_dir(self.key_dir)
        private: dict[str, str] = {}
        public: dict[str, str] = {}
        newest: tuple[float, str] | None = None
        for kid, _, _ in snap:
            if kid == LEGACY_KID:
                priv_p, pub_p = self.key_dir / "private.pem", self.key_dir / "public.pem"
            else:
                priv_p, pub_p = pairs[kid]["private"], pairs[kid]["public"]
            try:
                private[kid] = priv_p.read_text()
                public[kid] = pub_p.read_text()
            except OSError:
                continue
            mtime = priv_p.stat().st_mtime
            if newest is None or mtime > newest[0]:
                newest = (mtime, kid)
        self._private = private
        self._public = public
        self._current_kid = newest[1] if newest else None
        self._snapshot = snap

    def refresh(self, force: bool = False) -> bool:
        """Reload when the directory changed. Returns True when reloaded."""
        now = time.time()
        with self._lock:
            if not force and now - self._last_check < self.poll_seconds:
                return False
            self._last_check = now
            snap = self._take_snapshot()
            if snap != self._snapshot:
                self._load_snapshot(snap)
                return True
            return False

    def maybe_refresh(self) -> None:
        self.refresh(force=False)

    @property
    def kids(self) -> list[str]:
        with self._lock:
            return sorted(self._public)

    @property
    def current_kid(self) -> str | None:
        with self._lock:
            return self._current_kid

    def signing_key(self) -> tuple[str, str]:
        """Newest private key as (kid, pem). Raises KeyError when empty."""
        with self._lock:
            if not self._current_kid or self._current_kid not in self._private:
                raise KeyError("no signing key loaded")
            return self._current_kid, self._private[self._current_kid]

    def verification_key(self, kid: str | None) -> str:
        """Public key for a kid; unknown kids fall back to trying all keys."""
        with self._lock:
            if kid and kid in self._public:
                return self._public[kid]
            if kid is None and len(self._public) == 1:
                return next(iter(self._public.values()))
            raise KeyError(f"unknown kid: {kid}")

    def verification_keys(self) -> dict[str, str]:
        with self._lock:
            return dict(self._public)

    def jwks(self) -> dict:
        with self._lock:
            kids = sorted(self._public)
        return {"keys": [_public_to_jwk(self._public[k], k) for k in kids]}


def key_dir_configured() -> str | None:
    """Key directory from the environment, if set and non-empty."""
    value = os.getenv("BROKER_KEY_DIR")
    return value if value else None
