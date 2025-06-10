#!/bin/sh
set -e

if [ -n "$SSL_KEYFILE" ] && [ -n "$SSL_CERTFILE" ] \
    && [ -f "$SSL_KEYFILE" ] && [ -f "$SSL_CERTFILE" ]; then
    exec uvicorn api:app --host 0.0.0.0 --port 8000 \
        --ssl-keyfile "$SSL_KEYFILE" --ssl-certfile "$SSL_CERTFILE"
else
    exec uvicorn api:app --host 0.0.0.0 --port 8000
fi
