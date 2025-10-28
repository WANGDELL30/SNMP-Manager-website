# -----------------------------------------------------------------------------
# SNMPBackendrealcode.py (Consolidated & Trap-Ready)
# -----------------------------------------------------------------------------
# Backend SNMP Manager Pro
# - Flask + PySNMP
# - Firestore integration (via firebase_backend.py)
# - Frontend compatible (Adnan’s SNMP Manager Pro)
# -----------------------------------------------------------------------------
# Author : Adnan Yanuar x ChatGPT
# Version: v1.0.1
# Date   : 2025-10-23
# -----------------------------------------------------------------------------

# region: IMPORTS -------------------------------------------------------------
import os
import json
import uuid
import time
import random
from datetime import datetime, timezone
from typing import Tuple, Dict

from flask import Flask, request, jsonify
from flask_cors import CORS

# pysnmp (sync) for requests + trap sending
from pysnmp.hlapi import (
    SnmpEngine as SyncSnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd, setCmd, bulkCmd,
    OctetString, Integer32, NotificationType, sendNotification,
    UsmUserData, usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
    usmAesCfb128Protocol, usmNoAuthProtocol, usmNoPrivProtocol
)
from pysnmp.smi import builder, view

# trap receiver (asyncore carrier -> simple background thread)
from pysnmp.hlapi.asyncore import SnmpEngine as TrapSnmpEngine
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.rfc1902 import TimeTicks
from pysnmp.proto.rfc1902 import TimeTicks, ObjectIdentifier
# endregion -------------------------------------------------------------------

# region: OPTIONAL FIRESTORE (imported via firebase_backend)
try:
    from firebase_backend import save_sensor_data_to_cloud
    print("[import] firebase_backend loaded ✅")
except Exception as e:
    save_sensor_data_to_cloud = None
    print("[import] firebase_backend not available -> Firestore disabled. Reason:", e)
# endregion -------------------------------------------------------------------

# region: CONFIGURATION & ENV VARIABLES --------------------------------------
APP_ID_ENV   = os.getenv("APP_ID", "default-app-id")
USE_DUMMY    = os.getenv("DUMMY_MODE", "1") == "1"
SNMP_RETRIES = int(os.getenv("SNMP_RETRIES", "2"))
SNMP_TIMEOUT = float(os.getenv("SNMP_TIMEOUT", "1"))
MIB_DIR      = os.getenv("MIB_DIR", "./mibs")

# Dynamic walk page size
DEFAULT_BULK_PAGE = int(os.getenv("DEFAULT_BULK_PAGE_SIZE", "50"))

# Security toggle (hide community in production)
EXPOSE_COMMUNITY = os.getenv("EXPOSE_COMMUNITY_IN_META", "0") == "1"

# Trap listener config
TRAP_UDP_PORT = int(os.getenv("TRAP_UDP_PORT", "9162"))
TRAP_COMMUNITY = os.getenv("TRAP_COMMUNITY", "public")

# CORS origins
CORS_ALLOWED = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500").split(",")
    if o.strip()
]

print(f"[config] APP_ID={APP_ID_ENV} | DUMMY_MODE={USE_DUMMY} | TIMEOUT={SNMP_TIMEOUT}s | RETRIES={SNMP_RETRIES}")
print(f"[config] BULK_PAGE={DEFAULT_BULK_PAGE} | MIB_DIR={MIB_DIR}")
print(f"[config] CORS={CORS_ALLOWED} | EXPOSE_COMMUNITY={EXPOSE_COMMUNITY}")
print(f"[config] TRAP_PORT={TRAP_UDP_PORT} | TRAP_COMMUNITY={TRAP_COMMUNITY}")
# endregion -------------------------------------------------------------------

# region: FLASK & CORS SETUP --------------------------------------------------
app = Flask(__name__)
CORS(app, resources={
    r"/snmp": {"origins": CORS_ALLOWED},
    r"/health": {"origins": "*"},
    r"/version": {"origins": CORS_ALLOWED},
    r"/ping-agent": {"origins": CORS_ALLOWED},
    r"/notify": {"origins": CORS_ALLOWED},
    r"/trap-status": {"origins": CORS_ALLOWED},
})
# endregion -------------------------------------------------------------------

# region: MIB SETUP -----------------------------------------------------------
mibBuilder = builder.MibBuilder()
if os.path.isdir(MIB_DIR):
    mibBuilder.addMibSources(builder.DirMibSource(MIB_DIR))
mibView = view.MibViewController(mibBuilder)
# endregion -------------------------------------------------------------------

# region: PROTOCOL TEMPLATE ---------------------------------------------------
PROTOCOL_TEMPLATE: Dict[str, Dict] = {
    "1.3.6.1.4.1.9999.1.2.0": {"name": "temperature", "unit": "°C",  "category": "environment", "decimals": 2},
    "1.3.6.1.4.1.9999.1.2.1": {"name": "humidity",    "unit": "%RH", "category": "environment", "decimals": 2},
    "1.3.6.1.4.1.9999.1.2.2": {"name": "voltage",     "unit": "V",   "category": "power",       "decimals": 2},
    "1.3.6.1.4.1.9999.1.2.3": {"name": "current",     "unit": "A",   "category": "power",       "decimals": 2},
}
# endregion -------------------------------------------------------------------

# region: UTILITIES & HELPERS -------------------------------------------------
PROCESS_START_MONO = time.monotonic()

def _get_request_id() -> str:
    """Generate or read X-Request-Id from headers."""
    rid = request.headers.get("X-Request-Id") if request else None
    return rid or str(uuid.uuid4())

def _error(code: int, message: str, request_id: str, details: dict | None = None):
    """Standardized JSON error response."""
    payload = {"error": {"code": code, "message": message}}
    if details:
        payload["error"]["details"] = details
    payload["requestId"] = request_id
    return jsonify(payload), code

def _validate_v3(v3: dict) -> Tuple[bool, str]:
    """Validate SNMPv3 config dictionary."""
    user = (v3 or {}).get("user", "")
    authProto = (v3 or {}).get("authProto", "NONE").upper()
    privProto = (v3 or {}).get("privProto", "NONE").upper()
    authKey = (v3 or {}).get("authKey", "")
    privKey = (v3 or {}).get("privKey", "")
    if not user:
        return False, "SNMPv3 requires a username."
    if authProto != "NONE" and not authKey:
        return False, "Auth protocol set but no authKey."
    if privProto != "NONE" and not privKey:
        return False, "Priv protocol set but no privKey."
    return True, ""

def _security(version_str: str, community: str, v3: dict):
    """Build SNMP security parameters (v1/v2c/v3)."""
    vs = (version_str or "v2c").lower()
    if vs in ("v1", "v2c"):
        mp = 0 if vs == "v1" else 1
        return CommunityData(community, mpModel=mp)

    # SNMPv3
    user = (v3 or {}).get("user", "")
    authProto = (v3 or {}).get("authProto", "NONE").upper()
    privProto = (v3 or {}).get("privProto", "NONE").upper()
    authKey = (v3 or {}).get("authKey", "")
    privKey = (v3 or {}).get("privKey", "")

    auth_p = {
        "NONE": usmNoAuthProtocol,
        "SHA":  usmHMACSHAAuthProtocol,
        "MD5":  usmHMACMD5AuthProtocol,
    }.get(authProto, usmNoAuthProtocol)

    priv_p = {
        "NONE":   usmNoPrivProtocol,
        "AES128": usmAesCfb128Protocol,
    }.get(privProto, usmNoPrivProtocol)

    if auth_p is usmNoAuthProtocol and priv_p is usmNoPrivProtocol:
        return UsmUserData(user)
    elif priv_p is usmNoPrivProtocol:
        return UsmUserData(user, authKey, authProtocol=auth_p)
    else:
        return UsmUserData(user, authKey, privKey, authProtocol=auth_p, privProtocol=priv_p)

def _parse_object_identity(oid_str: str) -> ObjectType:
    """Accept numeric or MIB::symbol.index form."""
    if any(c.isalpha() for c in oid_str):
        if "::" in oid_str:
            left, right = oid_str.split("::", 1)
            parts = right.split(".")
            symbol = parts[0]
            indexes = []
            for p in parts[1:]:
                try:
                    indexes.append(int(p))
                except ValueError:
                    pass
            return ObjectType(ObjectIdentity(left, symbol, *indexes).resolveWithMib(mibView))
    return ObjectType(ObjectIdentity(oid_str))

def _to_number(v):
    """Convert to float if possible, else None."""
    try:
        if isinstance(v, (int, float)):
            return float(v)
        return float(str(v).strip())
    except Exception:
        return None

def _normalize_rows(results, ip, port):
    """Normalize SNMP results -> frontend-friendly rows."""
    ts = datetime.now(timezone.utc).isoformat()
    out = []
    for r in results or []:
        oid = r.get("oid")
        tpl = PROTOCOL_TEMPLATE.get(oid, {})
        name = r.get("name") or tpl.get("name") or oid
        unit = tpl.get("unit", "")
        category = tpl.get("category", "misc")
        t = r.get("type", "")

        num = _to_number(r.get("value"))
        if num is None:
            value_out = r.get("value")
        else:
            decimals = int(tpl.get("decimals", 2))
            value_out = round(num, decimals)

        out.append({
            "name": name,
            "oid": oid,
            "value": value_out,
            "unit": unit,
            "type": t,
            "category": category,
            "ts": ts,
            "ip": ip,
            "port": port,
            "source": "backend"
        })
    return out

def _make_meta(ip, operation, oid, version, community, port):
    """Generate metadata for Firestore + frontend."""
    meta = {
        "ip": ip,
        "operation": operation,
        "oid": oid,
        "version": version,
        "port": port,
        "appId": APP_ID_ENV,
        "dummy": USE_DUMMY,
    }
    if EXPOSE_COMMUNITY and version != "v3":
        meta["community"] = community
    else:
        meta["community"] = None
    return meta

def _save_to_firestore(meta: Dict, results, rows):
    """Save data to Firestore via firebase_backend."""
    if not save_sensor_data_to_cloud:
        print("[firebase] skipped (module not available)")
        return False, "disabled"
    payload = {**meta, "results": results, "rows": rows}
    ok, msg = save_sensor_data_to_cloud(payload, app_id=APP_ID_ENV)
    print("[firebase]", ok, "-", msg)
    return ok, msg
# endregion -------------------------------------------------------------------

# region: ROUTES --------------------------------------------------------------
@app.get("/mib/resolve")
def mib_resolve():
    """
    Resolve OID <-> MIB::symbol (contoh: ?q=SNMPv2-MIB::sysUpTime.0 atau ?q=1.3.6.1.2.1.1.3.0)
    """
    q = request.args.get("q", "")
    if not q:
        return _error(400, "query 'q' kosong", _get_request_id())

    try:
        # izinkan numeric OID atau MIB::symbol
        if "::" in q or any(c.isalpha() for c in q):
            oi = ObjectIdentity(*q.split("::")) if "::" in q else ObjectIdentity(q)
        else:
            oi = ObjectIdentity(q)

        oi = oi.resolveWithMib(mibView)
        mod, sym, idx = oi.getMibSymbol()
        return jsonify({
            "query": q,
            "module": mod,
            "symbol": sym,
            "index": idx,
            "oid": ".".join(str(x) for x in oi.getOid()),
            "pretty": f"{mod}::{sym}" + (("." + ".".join(map(str, idx))) if idx else "")
        }), 200
    except Exception as e:
        return _error(404, f"resolve gagal: {e}", _get_request_id())


@app.get("/mib/subtree")
def mib_subtree():
    """
    Jelajahi subtree dari base (numeric OID atau MIB::symbol) dengan NEXT/BULK.
    Example: /mib/subtree?base=SNMPv2-MIB::system&pageSize=50
    """
    base = request.args.get("base", "")
    page = int(request.args.get("pageSize", "50"))
    if not base:
        return _error(400, "param 'base' wajib", _get_request_id())

    try:
        obj = _parse_object_identity(base)
        target = UdpTransportTarget(("127.0.0.1", 161), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES)
        # pakai bulkCmd dengan dummy v2c ke localhost agar dapat struktur dari MIB tanpa agent nyata
        # (atau ganti dengan nextCmd bila ingin langkah-per-langkah)
        iterator = bulkCmd(SyncSnmpEngine(), CommunityData("public", mpModel=1),
                           target, ContextData(), 0, page, obj, lexicographicMode=False)
        items = []
        for ei, es, ei2, vbs in iterator:
            if ei or es:
                break
            for o, v in vbs:
                oi = ObjectIdentity(str(o)).resolveWithMib(mibView)
                mod, sym, idx = oi.getMibSymbol()
                items.append({
                    "oid": str(o),
                    "module": mod,
                    "symbol": sym,
                    "index": list(idx),
                    "type": v.__class__.__name__,
                })
        return jsonify({"base": base, "count": len(items), "items": items[:page]}), 200
    except Exception as e:
        return _error(500, f"subtree gagal: {e}", _get_request_id())

@app.get("/health")
def health():
    """Simple health check."""
    return {"ok": True, "dummy": USE_DUMMY, "appId": APP_ID_ENV}, 200

@app.get("/version")
def version():
    """Return backend version info for debugging/deploy visibility."""
    return {
        "version": os.getenv("APP_VERSION", "dev"),
        "buildTime": os.getenv("BUILD_TIME", ""),
    }, 200

@app.get("/ping-agent")
def ping_agent():
    """
    Test SNMP agent RTT latency by performing one simple SNMP GET (sysUpTime).
    Example: GET /ping-agent?ip=127.0.0.1&community=public&version=v2c
    """
    request_id = _get_request_id()
    ip = request.args.get("ip")
    community = request.args.get("community", "public")
    version = request.args.get("version", "v2c")
    oid = request.args.get("oid", "1.3.6.1.2.1.1.3.0")  # sysUpTime

    if not ip:
        return _error(400, "Missing 'ip' parameter", request_id)

    try:
        sec = _security(version, community, {})
        target = UdpTransportTarget((ip, 161), retries=SNMP_RETRIES, timeout=SNMP_TIMEOUT)
        target_obj = _parse_object_identity(oid)

        start = time.time()
        iterator = getCmd(SyncSnmpEngine(), sec, target, ContextData(), target_obj)
        for errorIndication, errorStatus, errorIndex, varBinds in iterator:
            if errorIndication:
                return _error(500, f"SNMP errorIndication: {errorIndication}", request_id)
            if errorStatus:
                return _error(500, f"SNMP errorStatus: {errorStatus.prettyPrint()}", request_id)
            break
        latency = round((time.time() - start) * 1000, 2)
        return {
            "ip": ip,
            "oid": oid,
            "latency_ms": latency,
            "status": "ok",
            "requestId": request_id,
        }, 200
    except Exception as e:
        return _error(500, str(e), request_id)

@app.post("/snmp")
def handle_snmp_request():
    """Main SNMP endpoint (GET/GETNEXT/WALK/SET)."""
    request_id = _get_request_id()
    t0 = time.time()

    # --- Input parsing ---
    try:
        if not request.is_json:
            return _error(415, "Content-Type must be application/json", request_id)

        data = request.get_json() or {}
        operation = (data.get("operation") or "").lower()
        ip = data.get("ip")
        oid = data.get("oid", "")
        setValue = data.get("setValue")
        port = int(data.get("port", 161))
        version = (data.get("version") or "v2c").lower()
        community = data.get("community", "public")
        v3_cfg = data.get("v3") or {}
        page_size = int(data.get("pageSize", DEFAULT_BULK_PAGE))

        if page_size < 1:
            page_size = 1
        elif page_size > 200:
            page_size = 200

        if not oid or not str(oid).strip():
            return _error(400, "Missing or empty 'oid'", request_id)

        if operation not in ("get", "getnext", "walk", "set"):
            return _error(400, "Invalid operation", request_id)

        if version == "v3":
            ok, msg = _validate_v3(v3_cfg)
            if not ok:
                return _error(400, msg, request_id)
        elif not all([operation, ip, oid, community]):
            return _error(400, "Missing required parameters", request_id)
    except Exception as e:
        return _error(400, f"Bad request: {e}", request_id)

    meta = _make_meta(ip, operation, oid, version, community, port)
    print(f"[request {request_id}] {operation.upper()} ip={ip} oid={oid} ver={version} pageSize={page_size} dummy={USE_DUMMY}")

    # --- Dummy Mode ---
    if USE_DUMMY:
        results = []
        rf = lambda a, b: f"{random.uniform(a, b):.2f}"

        if oid.startswith("1.3.6.1.4.1.9999.1.2") or ("9999.1.2" in oid):
            if operation == "walk":
                results = [
                    {"oid": "1.3.6.1.4.1.9999.1.2.0", "name": "temperature", "value": rf(20.0, 30.0), "type": "Float"},
                    {"oid": "1.3.6.1.4.1.9999.1.2.1", "name": "humidity", "value": rf(40.0, 70.0), "type": "Float"},
                    {"oid": "1.3.6.1.4.1.9999.1.2.2", "name": "voltage",  "value": rf(700.0, 800.0), "type": "Float"},
                    {"oid": "1.3.6.1.4.1.9999.1.2.3", "name": "current",  "value": rf(0.5, 2.0),     "type": "Float"},
                ]
            elif operation == "get":
                results = [{"oid": oid, "name": "temperature", "value": rf(20.0, 30.0), "type": "Float"}]
            elif operation == "getnext":
                results = [{"oid": oid, "name": "humidity", "value": rf(40.0, 70.0), "type": "Float"}]
            elif operation == "set":
                if not setValue:
                    return _error(400, "SET requires 'setValue'", request_id)
                results = [{"oid": oid, "name": "dummySet", "value": f"Value set to: {setValue}", "type": "OctetString"}]
        else:
            return _error(404, "Dummy Agent does not recognize this OID", request_id)

        for r in results:
            r["dummy"] = True

        rows = _normalize_rows(results, ip, port)
        latency_ms = int((time.time() - t0) * 1000)
        meta["latency_ms"] = latency_ms
        meta["requestId"] = request_id
        _save_to_firestore(meta, results, rows)
        return jsonify({"meta": meta, "results": results, "rows": rows}), 200

    # --- Real SNMP ---
    try:
        sec = _security(version, community, v3_cfg)
        target = UdpTransportTarget((ip, port), retries=SNMP_RETRIES, timeout=SNMP_TIMEOUT)
        target_obj = _parse_object_identity(oid)
        results = []

        if operation == "get":
            iterator = getCmd(SyncSnmpEngine(), sec, target, ContextData(), target_obj)
        elif operation == "getnext":
            iterator = nextCmd(SyncSnmpEngine(), sec, target, ContextData(), target_obj, lexicographicMode=False)
        elif operation == "set":
            if not setValue:
                return _error(400, "SET requires 'setValue'", request_id)
            val_to_set = OctetString(str(setValue).encode("utf-8"))
            iterator = setCmd(SyncSnmpEngine(), sec, target, ContextData(), ObjectType(ObjectIdentity(oid), val_to_set))
        elif operation == "walk":
            iterator = bulkCmd(SyncSnmpEngine(), sec, target, ContextData(), 0, page_size, target_obj, lexicographicMode=False)

        for errorIndication, errorStatus, errorIndex, varBinds in iterator:
            if errorIndication:
                return _error(500, f"SNMP errorIndication: {errorIndication}", request_id)
            if errorStatus:
                return _error(500, f"SNMP errorStatus: {errorStatus.prettyPrint()}", request_id)
            for oid_result, val_result in varBinds:
                try:
                    obj_id = ObjectIdentity(str(oid_result)).resolveWithMib(mibView)
                    name = obj_id.getMibSymbol()[1]
                except Exception:
                    name = str(oid_result)
                results.append({
                    "oid": str(oid_result),
                    "name": name,
                    "value": str(val_result),
                    "type": val_result.__class__.__name__,
                })
            if operation in ("get", "set", "getnext"):
                break

        rows = _normalize_rows(results, ip, port)
        latency_ms = int((time.time() - t0) * 1000)
        meta["latency_ms"] = latency_ms
        meta["requestId"] = request_id
        ok, msg = _save_to_firestore(meta, results, rows)
        print(f"[request {request_id}] save_to_firestore -> {ok} | {msg}")
        return jsonify({"meta": meta, "results": results, "rows": rows}), 200

    except Exception as e:
        return _error(500, str(e), request_id)
# endregion -------------------------------------------------------------------

# region: TRAP RECEIVER + SENDER ---------------------------------------------
import threading
import re

_trap_engine = None
_trap_thread = None
_OID_PATTERN = re.compile(r"^\d+(\.\d+)+$")

def _varbinds_to_rows(var_binds):
    rows = []
    for oid, val in var_binds:
        rows.append({
            "oid": str(oid),
            "value": str(val),
            "type": val.__class__.__name__,
        })
    return rows

def _trap_callback(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    try:
        transportDomain, transportAddress = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
        src_ip, src_port = transportAddress
    except Exception:
        src_ip, src_port = "unknown", 0

    rows = _varbinds_to_rows(varBinds)
    payload = {
        "ip": src_ip,
        "port": src_port,
        "operation": "trap",
        "version": "v1/v2c",
        "oid": rows[0]["oid"] if rows else None,
        "results": rows,
        "rows": [
            {
                **r,
                "category": "trap",
                "ts": datetime.now(timezone.utc).isoformat(),
                "ip": src_ip,
                "port": src_port,
                "source": "trap-listener"
            } for r in rows
        ],
        "meta": {"udpPort": TRAP_UDP_PORT, "appId": APP_ID_ENV, "dummy": USE_DUMMY},
    }

    if save_sensor_data_to_cloud:
        try:
            ok, msg = save_sensor_data_to_cloud(payload, app_id=APP_ID_ENV, collection_suffix="snmp-traps")
            print(f"[trap] from {src_ip}:{src_port} -> save={ok} | {msg}")
        except Exception as e:
            print(f"[trap] firebase error: {e}")
    else:
        print(f"[trap] (firebase disabled) from {src_ip}:{src_port}: {rows}")

def _trap_thread_runner():
    global _trap_engine
    try:
        _trap_engine = TrapSnmpEngine()
        config.addV1System(_trap_engine, 'trap-area', TRAP_COMMUNITY)
        config.addTransport(
            _trap_engine,
            udp.domainName,
            udp.UdpTransport().openServerMode(('0.0.0.0', TRAP_UDP_PORT))
        )
        ntfrcv.NotificationReceiver(_trap_engine, _trap_callback)
        print(f"[startup] Trap receiver listening on UDP {TRAP_UDP_PORT} (community='{TRAP_COMMUNITY}')")
        _trap_engine.transportDispatcher.jobStarted(1)
        try:
            _trap_engine.transportDispatcher.runDispatcher()  # blocks in this thread
        finally:
            try:
                _trap_engine.transportDispatcher.closeDispatcher()
            except Exception:
                pass
    except Exception as e:
        print(f"[trap] receiver failed to start: {e}")

def start_trap_receiver_background():
    """Start trap receiver in a daemon thread (idempotent)."""
    global _trap_thread
    if _trap_thread and _trap_thread.is_alive():
        return
    _trap_thread = threading.Thread(target=_trap_thread_runner, name="snmp-trap-listener", daemon=True)
    _trap_thread.start()

@app.get("/trap-status")
def trap_status():
    """Quick check to see if trap listener thread/engine is alive."""
    status = {
        "listening": bool(_trap_thread and _trap_thread.is_alive()),
        "port": TRAP_UDP_PORT,
        "community": TRAP_COMMUNITY,
        "appId": APP_ID_ENV
    }
    return jsonify(status), 200

def _make_object_type(oid_str: str, value):
    """
    Convert JSON varbind (oid, value) into an ObjectType with sensible defaults:
      - numeric OID strings become ObjectIdentity(oid)
      - values: int->Integer32, str-oid->ObjectIdentity(value), else->OctetString
    """
    base_oid = ObjectIdentity(oid_str)
    if isinstance(value, int):
        val = Integer32(value)
    elif isinstance(value, str) and _OID_PATTERN.match(value):
        val = ObjectIdentity(value)
    else:
        val = OctetString(str(value))
    return ObjectType(base_oid, val)

@app.post("/notify")
def send_trap_or_inform():
    """
    Send SNMPv2c TRAP or INFORM to target.
    JSON example:
    {
      "targetIp": "127.0.0.1",
      "targetPort": 9162,
      "community": "public",
      "type": "trap",                  # or "inform"
      "enterpriseOid": "1.3.6.1.4.1.9999.1.0",
      "varbinds": [
        ["1.3.6.1.4.1.9999.1.2.0", 27],      # temperature
        ["1.3.6.1.4.1.9999.1.2.1", "65"]     # humidity
      ]
    }
    """
    request_id = _get_request_id()
    try:
        body = request.get_json(force=True) or {}
        target_ip = str(body.get("targetIp", "127.0.0.1"))
        target_port = int(body.get("targetPort", TRAP_UDP_PORT))
        community = str(body.get("community", "public"))
        notif_type = str(body.get("type", "trap")).lower()
        enterprise_oid = str(body.get("enterpriseOid", "1.3.6.1.4.1.9999.1.0"))
        vb_pairs = body.get("varbinds", [])

        sysuptime_ticks = int((time.monotonic() - PROCESS_START_MONO) * 100)

        pdu = NotificationType(ObjectIdentity(enterprise_oid))
        base_vbs = [
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'), TimeTicks(sysuptime_ticks)),        # sysUpTime.0
            ObjectType(ObjectIdentity('1.3.6.1.6.3.1.1.4.1.0'), ObjectIdentifier(enterprise_oid)), # snmpTrapOID.0
        ]
        extra_vbs = [_make_object_type(str(oid), val) for oid, val in vb_pairs]

        iterator = sendNotification(
            SyncSnmpEngine(),
            CommunityData(community, mpModel=1),   # v2c
            UdpTransportTarget((target_ip, target_port), timeout=2, retries=1),
            ContextData(),
            notif_type,  # 'trap' or 'inform'
            pdu.addVarBinds(*(base_vbs + extra_vbs))
        )

        # Iterate the generator to actually send
        err = None
        for (errorIndication, errorStatus, errorIndex, varBinds) in iterator:
            if errorIndication:
                err = f"errorIndication: {errorIndication}"
                break
            if errorStatus:
                idx = int(errorIndex) and int(errorIndex) - 1
                err = f"errorStatus: {errorStatus.prettyPrint()} at index {idx}"
                break

        if err:
            return _error(500, f"sendNotification failed: {err}", request_id)

        return jsonify({
            "ok": True,
            "message": f"Sent {notif_type.upper()} to {target_ip}:{target_port}",
            "requestId": request_id
        }), 200

    except Exception as e:
        return _error(500, f"/notify failed: {e}", request_id)
# endregion -------------------------------------------------------------------

# region: MAIN ENTRYPOINT -----------------------------------------------------
if __name__ == "__main__":
    # Start the trap listener BEFORE the web server
    start_trap_receiver_background()

    port = int(os.getenv("PORT", "5000"))
    print(f"[startup] SNMP Backend running on 0.0.0.0:{port}")
    # Avoid double-spawning threads due to Flask reloader
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
# endregion -------------------------------------------------------------------
