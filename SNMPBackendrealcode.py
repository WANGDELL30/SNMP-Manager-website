# -----------------------------------------------------------------------------
# SNMPBackendrealcode.py (Final Version with Documentation)
# -----------------------------------------------------------------------------
# Backend SNMP Manager Pro
# - Flask + PySNMP
# - Firestore integration (via firebase_backend.py)
# - Frontend compatible (Adnan’s SNMP Manager Pro)
# -----------------------------------------------------------------------------
# Author : Adnan Yanuar x ChatGPT
# Version: v1.0.0
# Date   : 2025-10-07
# -----------------------------------------------------------------------------

# region: IMPORTS -------------------------------------------------------------
import os
import json
import uuid
import time
import random
from datetime import datetime, timezone
from typing import Tuple, List, Dict

from flask import Flask, request, jsonify
from flask_cors import CORS

# pysnmp core modules
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd, setCmd, bulkCmd,
    OctetString, Integer32,
    UsmUserData, usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
    usmAesCfb128Protocol, usmNoAuthProtocol, usmNoPrivProtocol
)
from pysnmp.smi import builder, view
# endregion ------------------------------------------------------------------

# region: OPTIONAL FIRESTORE (imported via firebase_backend)
try:
    from firebase_backend import save_sensor_data_to_cloud
    print("[import] firebase_backend loaded ✅")
except Exception as e:
    save_sensor_data_to_cloud = None
    print("[import] firebase_backend not available -> Firestore disabled. Reason:", e)
# endregion ------------------------------------------------------------------

# region: CONFIGURATION & ENV VARIABLES --------------------------------------
APP_ID_ENV   = os.getenv("APP_ID", "default-app-id")
USE_DUMMY    = os.getenv("DUMMY_MODE", "1") == "1"
SNMP_RETRIES = int(os.getenv("SNMP_RETRIES", "2"))
SNMP_TIMEOUT = float(os.getenv("SNMP_TIMEOUT", "1"))
MIB_DIR      = os.getenv("MIB_DIR", "./mibs")

# Dynamic walk page size
DEFAULT_BULK_PAGE = int(os.getenv("DEFAULT_BULK_PAGE_SIZE", "50"))

# Firestore key (used by firebase_backend)
FIREBASE_KEY_PATH = os.getenv("FIREBASE_KEY_PATH", "./serviceAccountKey.json")

# Security toggle (hide community in production)
EXPOSE_COMMUNITY = os.getenv("EXPOSE_COMMUNITY_IN_META", "0") == "1"

# CORS
CORS_ALLOWED = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500").split(",")
    if o.strip()
]

print(f"[config] APP_ID={APP_ID_ENV} | DUMMY_MODE={USE_DUMMY} | TIMEOUT={SNMP_TIMEOUT}s | RETRIES={SNMP_RETRIES}")
print(f"[config] BULK_PAGE={DEFAULT_BULK_PAGE} | MIB_DIR={MIB_DIR}")
print(f"[config] CORS={CORS_ALLOWED} | EXPOSE_COMMUNITY={EXPOSE_COMMUNITY}")
# endregion ------------------------------------------------------------------

# region: FLASK SETUP --------------------------------------------------------
app = Flask(__name__)
CORS(app, resources={r"/snmp": {"origins": CORS_ALLOWED}, r"/health": {"origins": "*"}})
# endregion ------------------------------------------------------------------

# region: MIB SETUP ----------------------------------------------------------
mibBuilder = builder.MibBuilder()
if os.path.isdir(MIB_DIR):
    mibBuilder.addMibSources(builder.DirMibSource(MIB_DIR))
mibView = view.MibViewController(mibBuilder)
# endregion ------------------------------------------------------------------

# region: PROTOCOL TEMPLATE --------------------------------------------------
PROTOCOL_TEMPLATE: Dict[str, Dict] = {
    "1.3.6.1.4.1.9999.1.2.0": {"name": "temperature", "unit": "°C",  "category": "environment", "decimals": 2},
    "1.3.6.1.4.1.9999.1.2.1": {"name": "humidity",    "unit": "%RH", "category": "environment", "decimals": 2},
    "1.3.6.1.4.1.9999.1.2.2": {"name": "voltage",     "unit": "V",   "category": "power",       "decimals": 2},
    "1.3.6.1.4.1.9999.1.2.3": {"name": "current",     "unit": "A",   "category": "power",       "decimals": 2},
}
# endregion ------------------------------------------------------------------

# region: UTILITIES & HELPERS ------------------------------------------------
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
            indexes = [int(p) for p in parts[1:] if p.isdigit()]
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
# endregion ------------------------------------------------------------------

# === LANJUT KE BAGIAN 2 ===
# region: ROUTES -------------------------------------------------------------

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
        iterator = getCmd(SnmpEngine(), sec, target, ContextData(), target_obj)
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
                    {"oid": "1.3.6.1.4.1.9999.1.2.2", "name": "voltage", "value": rf(700.0, 800.0), "type": "Float"},
                    {"oid": "1.3.6.1.4.1.9999.1.2.3", "name": "current", "value": rf(0.5, 2.0), "type": "Float"},
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

        # Mark dummy
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
            iterator = getCmd(SnmpEngine(), sec, target, ContextData(), target_obj)
        elif operation == "getnext":
            iterator = nextCmd(SnmpEngine(), sec, target, ContextData(), target_obj, lexicographicMode=False)
        elif operation == "set":
            if not setValue:
                return _error(400, "SET requires 'setValue'", request_id)
            val_to_set = OctetString(str(setValue).encode("utf-8"))
            iterator = setCmd(SnmpEngine(), sec, target, ContextData(), ObjectType(ObjectIdentity(oid), val_to_set))
        elif operation == "walk":
            iterator = bulkCmd(SnmpEngine(), sec, target, ContextData(), 0, page_size, target_obj, lexicographicMode=False)

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

# endregion ------------------------------------------------------------------

# region: MAIN ENTRYPOINT ----------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    print(f"[startup] SNMP Backend running on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
    
    # --- Trap Receiver (async) ---
import asyncio
from pysnmp.hlapi.asyncio import SnmpEngine
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config
from pysnmp.entity.rfc3413 import ntfrcv

TRAP_UDP_PORT = int(os.getenv("TRAP_UDP_PORT", "9162"))

_snmp_engine_trap = None

def _normalize_var_binds(var_binds):
    rows = []
    for oid, val in var_binds:
        rows.append({
            "oid": str(oid),
            "value": str(val),
            "type": val.__class__.__name__,
        })
    return rows

async def _run_trap_receiver(app_id_env: str):
    global _snmp_engine_trap
    if _snmp_engine_trap is not None:
        return

    _snmp_engine_trap = SnmpEngine()

    # v1/v2c community (optional: dari ENV, default "public")
    community = os.getenv("TRAP_COMMUNITY", "public")
    config.addV1System(_snmp_engine_trap, 'my-area', community)
    config.addTransport(
        _snmp_engine_trap,
        udp.domainName,
        udp.UdpTransport().openServerMode(('0.0.0.0', TRAP_UDP_PORT))
    )

    async def cb_trap(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
        transportDomain, transportAddress = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
        src_ip, src_port = transportAddress
        rows = _normalize_var_binds(varBinds)

        payload = {
            "ip": src_ip,
            "port": src_port,
            "operation": "trap",
            "version": "v2c/v1",  # simple label; bisa diperluas jika pakai v3
            "oid": rows[0]["oid"] if rows else None,  # first OID as hint
            "results": rows,  # simpan juga sebagai results[]
            "rows": [
                {**r, "category": "trap", "ts": datetime.utcnow().isoformat() + "Z", "ip": src_ip, "port": src_port}
                for r in rows
            ],
            "meta": {"source": "trap-listener", "udpPort": TRAP_UDP_PORT},
        }

        from firebase_backend import save_sensor_data_to_cloud
        ok, msg = save_sensor_data_to_cloud(payload, app_id=app_id_env, collection_suffix="snmp-traps")
        print(f"[trap] from {src_ip}:{src_port} -> save={ok} | {msg}")

    ntfrcv.NotificationReceiver(_snmp_engine_trap, cb_trap)

    print(f"[startup] Trap receiver listening on UDP {TRAP_UDP_PORT}")
    await _snmp_engine_trap.transportDispatcher.jobStarted(1)  # keep running
    try:
        await _snmp_engine_trap.transportDispatcher.runDispatcher()
    except Exception as e:
        print(f"[trap] receiver error: {e}")
        _snmp_engine_trap.transportDispatcher.closeDispatcher()

def start_trap_receiver_background(app_id_env: str):
    # Jalankan event loop asyncio di thread terpisah supaya Flask tetap jalan
    import threading
    def _runner():
        asyncio.run(_run_trap_receiver(app_id_env))
    th = threading.Thread(target=_runner, daemon=True)
    th.start()
    
    from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, NotificationType, sendNotification
)

@app.post("/notify")
def send_trap_or_inform():
    target_ip = request.json.get("targetIp", "127.0.0.1")
    target_port = int(request.json.get("targetPort", 9162))
    community = request.json.get("community", "public")
    notif_type = request.json.get("type", "trap")  # "trap" or "inform"
    enterprise_oid = request.json.get("enterpriseOid", "1.3.6.1.4.1.9999.1.0")
    varbinds = request.json.get("varbinds", [
        ["1.3.6.1.2.1.1.3.0", 1234],  # sysUpTimeInstance
        ["1.3.6.1.6.3.1.1.4.1.0", enterprise_oid],  # snmpTrapOID.0
    ])

    engine = SnmpEngine()
    cd = CommunityData(community, mpModel=1)  # v2c
    target = UdpTransportTarget((target_ip, target_port), timeout=1, retries=1)

    pdu = NotificationType(ObjectIdentity(enterprise_oid))
    for oid, value in varbinds:
        pdu = pdu.addVarBinds(ObjectType(ObjectIdentity(oid), value))

    if notif_type.lower() == "inform":
        sendNotification(engine, cd, target, ContextData(), 'inform', pdu)
    else:
        sendNotification(engine, cd, target, ContextData(), 'trap', pdu)

    return {"ok": True, "message": f"Sent {notif_type.upper()} to {target_ip}:{target_port}"}


# endregion ------------------------------------------------------------------
