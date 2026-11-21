from __future__ import annotations

from urllib.parse import urlsplit


class ApiBaseUrlError(ValueError):
    """Raised when an API client target is outside the supported transport boundary."""


def validate_api_base_url(value: str) -> str:
    """Require HTTPS remotely and plain HTTP only for loopback development services."""
    raw = value.strip()
    try:
        parts = urlsplit(raw)
        _ = parts.port
    except ValueError as exc:
        raise ApiBaseUrlError("BLACK ICE API URL is malformed") from exc
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ApiBaseUrlError(
            "BLACK ICE API URL must be an HTTP(S) origin without credentials or a path"
        )
    hostname = parts.hostname.lower().rstrip(".")
    if parts.scheme.lower() == "http" and hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ApiBaseUrlError("remote BLACK ICE endpoints must use HTTPS")
    return raw.rstrip("/")
