"""
local_storage.py — Store uploaded files on the backend's own disk.

Used when settings.storage_backend == "local" (the default). This requires
no external service or billing setup, which makes it a good fit for demos —
but by default it lives on the container's ephemeral filesystem, so files
are lost on every redeploy/restart unless you attach a Railway volume
mounted at the same path as settings.local_storage_path.

Swap to settings.storage_backend = "firebase" (see app/services/firebase.py)
once real Storage is provisioned (Blaze plan) for durable, production use.
"""

import os
from pathlib import Path

from app.config import settings


def _resolve(dest_relative_path: str) -> Path:
    """Resolve a relative path under the storage root, guarding against path traversal."""
    base = Path(settings.local_storage_path).resolve()
    full_path = (base / dest_relative_path).resolve()
    if not full_path.is_relative_to(base):
        raise ValueError("Invalid path")
    return full_path


def save_file_locally(file_bytes: bytes, dest_relative_path: str) -> str:
    """Write bytes to disk under the storage root. Returns the relative path."""
    full_path = _resolve(dest_relative_path)
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_bytes(file_bytes)
    return dest_relative_path


def resolve_local_path(dest_relative_path: str) -> Path:
    """Resolve (and validate) a stored file's path for serving it back."""
    return _resolve(dest_relative_path)
