# Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (optional: tzdata, netcat for debug)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential tzdata && \
    rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt waitress

# App files
COPY app_main.py routes_snmp.py firebase_backend.py ./

# Runtime env defaults (override via -e)
ENV PORT=5000 \
    ENABLE_TRAP_RECEIVER=1 \
    TRAP_UDP_PORT=9162

EXPOSE 5000/tcp
EXPOSE 9162/udp

# Start with waitress (production WSGI)
# Note: app_main.py creates the app when invoked — we can run it directly,
# but here’s an example using waitress-serve for robustness.
CMD ["python", "app_main.py"]
# alternatif (kalau mau waitress-serve)
# CMD ["waitress-serve", "--listen=0.0.0.0:5000", "app_main:create_app"]
# alternatif (kalau mau debug pake flask langsung)