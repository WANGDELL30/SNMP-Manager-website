# routes_snmp.py — SNMP via snmpy (tanpa pysnmp)
from __future__ import annotations
import os, time, random
from datetime import datetime, timezone
from typing import Any, Dict, List
from flask import Blueprint, request, jsonify
from easysnmp import Session as SnmpSession

# Firestore helper (opsional)
try:
    from firebase_backend import save_sensor_data_to_cloud  # type: ignore
except Exception:
    save_sensor_data_to_cloud = None

api = Blueprint("api", __name__)

APP_ID        = os.getenv("APP_ID", "default-app-id")
DEFAULT_LIMIT = max(1, min(200, int(os.getenv("SNMP_PAGE_SIZE", "50"))))

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _row(oid: str, value: Any, ip: str, port: int, name: str | None = None) -> Dict[str, Any]:
    s = value if isinstance(value, (int, float)) else str(value)
    nm = name or oid
    unit = None
    lname = nm.lower()
    if "temp" in lname or "temperature" in lname: unit = "°C"
    elif "humid" in lname: unit = "%RH"
    elif "volt"  in lname: unit = "V"
    elif "curr"  in lname or "amp" in lname: unit = "A"
    return {
        "name": nm,
        "oid": oid,
        "value": s,
        "unit": unit,
        "type": type(value).__name__,
        "category": "environment" if unit in ("°C", "%RH") else "power",
        "ts": _now_iso(),
        "ip": ip,
        "port": port,
        "source": "BK"  # backend
    }

def _dummy(ip: str, port: int):
    base = "1.3.6.1.4.1.9999.1.2"
    rows = [
        _row(f"{base}.0", round(24 + random.random()*6, 2), ip, port, "temperature"),
        _row(f"{base}.1", round(50 + random.random()*10, 2), ip, port, "humidity"),
        _row(f"{base}.2", round(700 + random.random()*100, 2), ip, port, "voltage"),
        _row(f"{base}.3", round(0.3 + random.random()*1.5, 2), ip, port, "current"),
    ]
    # results versi ringkas untuk debugging
    results = [{"oid": r["oid"], "value": r["value"], "type": r["type"]} for r in rows]
    return results, rows

@api.post("/snmp")
def snmp_handler():
    """
    Body:
      {operation: get|getnext|walk|set, ip, port, version: v1|v2c, community, oid, setValue?, pageSize?}
    """
    t0 = time.time()
    DUMMY_MODE = os.getenv("DUMMY_MODE", "0") == "1"

    data = request.get_json(force=True, silent=True) or {}
    op  = str(data.get("operation", "get")).lower()
    ip  = str(data.get("ip", "127.0.0.1"))
    oid = str(data.get("oid", "1.3.6.1.2.1.1.1.0"))
    port = int(data.get("port", 161))
    ver  = str(data.get("version", "v2c")).lower()
    comm = str(data.get("community", "public"))
    set_value = data.get("setValue")
    limit = max(1, min(200, int(data.get("pageSize", DEFAULT_LIMIT))))
    req_id = request.headers.get("X-Request-Id") or data.get("requestId")

    try:
        if DUMMY_MODE:
            results, rows = _dummy(ip, port)
        else:
            sess = SnmpSession(host=ip, community=comm, version=ver)
            results: List[Dict[str, Any]] = []
            rows: List[Dict[str, Any]] = []

            if op == "get":
                val = sess.get(oid)
                results.append({"oid": oid, "value": val, "type": type(val).__name__})
                rows.append(_row(oid, val, ip, port))

            elif op in ("getnext", "walk"):
                cnt = 0
                for k, v in sess.walk(oid):
                    k = str(k)
                    results.append({"oid": k, "value": v, "type": type(v).__name__})
                    rows.append(_row(k, v, ip, port))
                    cnt += 1
                    if op == "getnext" or (op == "walk" and cnt >= limit):
                        break

            elif op == "set":
                if set_value is None:
                    return jsonify({"ok": False, "message": "SET requires 'setValue'"}), 400
                sess.set(oid, set_value)
                results.append({"oid": oid, "value": set_value, "type": type(set_value).__name__})
                rows.append(_row(oid, set_value, ip, port))
            else:
                return jsonify({"ok": False, "message": f"Unsupported operation: {op}"}), 400

        latency_ms = int((time.time() - t0) * 1000)
        payload = {
            "ip": ip, "port": port, "operation": op, "oid": oid, "version": ver,
            "results": results, "rows": rows, "meta": {"latency_ms": latency_ms, "source": "snmp-endpoint"}
        }

        saved = False; msg = "Firestore disabled"
        if save_sensor_data_to_cloud:
            ok, msg = save_sensor_data_to_cloud(payload, app_id=APP_ID, request_id=req_id)
            saved = bool(ok)

        return jsonify({
            "ok": True,
            "latency_ms": latency_ms,
            "count": {"results": len(results), "rows": len(rows)},
            "saved": saved, "saveMessage": msg,
            "rows": rows,     # ← frontend kamu baca kolom dari sini
            "data": payload
        }), 200

    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500

@api.get("/health")
def health():
    return jsonify({"ok": True, "ts": _now_iso(), "appId": APP_ID})
