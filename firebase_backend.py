# firebase_backend.py
# -----------------------------------------------------------------------------
# Firestore helper untuk SNMP Manager backend (Admin SDK)
#
# ✅ Fitur utama (patched & final):
#   - Deteksi emulator benar (pakai FIRESTORE_EMULATOR_HOST, bukan FIREBASE_…)
#   - Thread-safe, idempotent initialization
#   - Retry ringan untuk error transient (ServiceUnavailable, DeadlineExceeded, Aborted)
#   - Guard payload besar (>~900KB) → otomatis split ke normalized-rows
#   - Tambahan field opsional: requestId, meta, dummy
#   - Pesan error lebih jelas
#   - Logging prefiks konsisten
# -----------------------------------------------------------------------------

# coding salah
#pip tolongin gue

from __future__ import annotations

import os
import sys
import json
import time
import threading
from typing import Optional, Tuple, List, Dict, Any, Callable

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
except Exception as e:
    raise RuntimeError("[firebase_backend] Missing dependency 'firebase-admin'. Install it with: pip install firebase-admin") from e

try:
    from google.api_core.exceptions import ServiceUnavailable, DeadlineExceeded, Aborted
except Exception:
    ServiceUnavailable = DeadlineExceeded = Aborted = Exception  # fallback


_DB: Optional[firestore.Client] = None
_APP_INIT_DONE: bool = False
_INIT_LOCK = threading.Lock()


def _debug(msg: str) -> None:
    print(f"[firebase_backend] {msg}")


def _resolve_key_path(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit
    return os.getenv("FIREBASE_KEY_PATH") or os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or "serviceAccountKey.json"


def _using_emulator() -> bool:
    return bool(os.getenv("FIRESTORE_EMULATOR_HOST"))


def initialize_firebase_admin(key_path: Optional[str] = None) -> Optional[firestore.Client]:
    global _DB, _APP_INIT_DONE
    if _DB is not None:
        return _DB

    with _INIT_LOCK:
        if _DB is not None:
            return _DB

        resolved = _resolve_key_path(key_path)
        emulator = _using_emulator()

        try:
            if not _APP_INIT_DONE:
                if emulator:
                    _debug("Detected FIRESTORE_EMULATOR_HOST -> initializing app for emulator (no credentials).")
                    if not firebase_admin._apps:
                        firebase_admin.initialize_app()
                    _APP_INIT_DONE = True
                else:
                    if not resolved or not os.path.exists(resolved):
                        _debug(f"Service account key not found at: {resolved!r}")
                        _debug(
                            "Firestore writes skipped. "
                            "Set FIREBASE_KEY_PATH or GOOGLE_APPLICATION_CREDENTIALS to valid JSON, "
                            "or set FIRESTORE_EMULATOR_HOST for emulator."
                        )
                        return None
                    _debug(f"Initializing Firebase Admin with key: {os.path.abspath(resolved)}")
                    cred = credentials.Certificate(resolved)
                    if not firebase_admin._apps:
                        firebase_admin.initialize_app(cred)
                    _APP_INIT_DONE = True

            _DB = firestore.client()
            _debug("Firebase Admin initialized ✅")
            return _DB

        except Exception as e:
            _debug(f"ERROR initializing Firebase Admin: {e}")
            return None


def _sanitize_app_id(app_id: Optional[str]) -> str:
    app_id = app_id or os.getenv("APP_ID", "default-app-id")
    app_id = str(app_id).strip().replace("/", "-").replace("\\", "-").replace(" ", "-")
    return app_id or "default-app-id"


def _data_root(db: firestore.Client, app_id: str):
    return (
        db.collection("artifacts")
          .document(app_id)
          .collection("public")
          .document("data")
    )


def _commit_with_retry(fn: Callable[[], Any], *, max_attempts: int = 3, base_sleep: float = 0.2):
    attempt = 0
    while True:
        try:
            return fn()
        except (ServiceUnavailable, DeadlineExceeded, Aborted) as e:
            attempt += 1
            if attempt >= max_attempts:
                raise
            sleep_for = base_sleep * (2 ** (attempt - 1))
            _debug(f"Transient Firestore error ({type(e).__name__}): retrying in {sleep_for:.2f}s (attempt {attempt}/{max_attempts})")
            time.sleep(sleep_for)


def _approx_size(obj: Any) -> int:
    try:
        return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except Exception:
        return sys.getsizeof(obj)


_MAX_DOC_SIZE = 900_000  # safety margin di bawah 1MiB


def save_sensor_data_to_cloud(
    data: Dict[str, Any],
    app_id: Optional[str] = None,
    *,
    collection_suffix: str = "sensor-readings-from-backend",
    request_id: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
    dummy: Optional[bool] = None,
) -> Tuple[bool, str]:
    if not isinstance(data, dict):
        return False, "Data must be a dict."

    db = initialize_firebase_admin()
    if db is None:
        return False, (
            "Firebase not initialized. Set FIREBASE_KEY_PATH or GOOGLE_APPLICATION_CREDENTIALS, "
            "or set FIRESTORE_EMULATOR_HOST for emulator."
        )

    app_id = _sanitize_app_id(app_id)
    col = _data_root(db, app_id).collection(collection_suffix)

    to_write = {**data, "serverTimestamp": firestore.SERVER_TIMESTAMP}
    if request_id: to_write["requestId"] = request_id
    if meta: to_write["meta"] = meta
    if dummy is not None: to_write["dummy"] = bool(dummy)

    payload_size = _approx_size(to_write)

    if payload_size > _MAX_DOC_SIZE:
        rows = data.get("rows") or data.get("results") or []
        count = len(rows) if isinstance(rows, list) else 0

        header = {
            **{k: v for k, v in to_write.items() if k not in ("rows", "results")},
            "note": "payload too large, rows saved separately",
            "rowCount": count,
            "serverTimestamp": firestore.SERVER_TIMESTAMP,
        }

        _debug(f"Payload ~{payload_size} bytes exceeds limit; splitting to header + normalized-rows (rows={count})")
        try:
            _commit_with_retry(lambda: col.add(header))
        except Exception as e:
            return False, f"Failed to save header for large payload: {e}"

        if count == 0:
            return True, f"Large payload header saved; no rows to split."

        ok2, msg2 = save_rows_batch_to_cloud(
            rows if isinstance(rows, list) else [],
            app_id=app_id,
            collection_suffix="normalized-rows",
        )
        return (ok2, f"Large payload split -> {msg2}")

    try:
        _commit_with_retry(lambda: col.add(to_write))
        _debug(f"Wrote 1 doc to artifacts/{app_id}/public/data/{collection_suffix} (reqId={request_id})")
        return True, f"Saved to artifacts/{app_id}/public/data/{collection_suffix}"
    except Exception as e:
        return False, f"Failed to save: {e}"


def save_rows_batch_to_cloud(
    rows: List[Dict[str, Any]],
    app_id: Optional[str] = None,
    *,
    collection_suffix: str = "normalized-rows",
    chunk_size: int = 400,
    request_id: Optional[str] = None,
) -> Tuple[bool, str]:
    if not isinstance(rows, list):
        return False, "Rows must be a list."
    if not rows:
        return True, "No rows to write."

    db = initialize_firebase_admin()
    if db is None:
        return False, (
            "Firebase not initialized. Set FIREBASE_KEY_PATH or GOOGLE_APPLICATION_CREDENTIALS, "
            "or set FIRESTORE_EMULATOR_HOST for emulator."
        )

    app_id = _sanitize_app_id(app_id)
    col = _data_root(db, app_id).collection(collection_suffix)

    try:
        total = 0
        for i in range(0, len(rows), chunk_size):
            chunk = rows[i:i + chunk_size]
            batch = db.batch()
            for r in chunk:
                doc_ref = col.document()
                payload = {**r, "serverTimestamp": firestore.SERVER_TIMESTAMP}
                if request_id: payload["requestId"] = request_id
                batch.set(doc_ref, payload)

            _commit_with_retry(batch.commit)
            total += len(chunk)
            _debug(f"Batch committed ({len(chunk)} docs) -> artifacts/{app_id}/public/data/{collection_suffix} (acc={total}, reqId={request_id})")

        return True, f"Wrote {total} rows to artifacts/{app_id}/public/data/{collection_suffix}"
    except Exception as e:
        return False, f"Batch write failed: {e}"


def can_write(app_id: Optional[str] = None) -> Tuple[bool, str]:
    db = initialize_firebase_admin()
    if db is None:
        return False, (
            "Firebase not initialized. Set FIREBASE_KEY_PATH or GOOGLE_APPLICATION_CREDENTIALS, "
            "or set FIRESTORE_EMULATOR_HOST for emulator."
        )

    app_id = _sanitize_app_id(app_id)
    col = _data_root(db, app_id).collection("connectivity-check")

    try:
        _commit_with_retry(lambda: col.add({"ok": True, "serverTimestamp": firestore.SERVER_TIMESTAMP}))
        return True, f"Connectivity OK for artifacts/{app_id}/public/data/connectivity-check"
    except Exception as e:
        return False, f"Connectivity test failed: {e}"


if __name__ == "__main__":
    _debug("Running local test...")
    ok, msg = can_write()
    _debug(f"can_write -> {ok} | {msg}")
