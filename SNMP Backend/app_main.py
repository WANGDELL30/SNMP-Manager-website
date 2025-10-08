# app_main.py — launcher Flask (register blueprint routes_snmp)
from __future__ import annotations
import os
from flask import Flask
from flask_cors import CORS

from routes_snmp import api  # blueprint

APP_ID = os.getenv("APP_ID", "default-app-id")
CORS_ORIGINS = [
    o.strip() for o in os.getenv(
        "CORS_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500"
    ).split(",") if o.strip()
]

def create_app():
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": CORS_ORIGINS}})
    app.register_blueprint(api)
    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("PORT", "5000"))
    print(f"[startup] SNMP Backend (snmpy) on 0.0.0.0:{port} | APP_ID={APP_ID}")
    app.run(host="0.0.0.0", port=port, debug=True)
