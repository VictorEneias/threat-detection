#!/bin/sh
set -e

# Update CVE database if possible
if [ -d "cve-db/cve-search" ]; then
    echo "Updating CVE database..."
    cve-db/cve-search/sbin/db_updater.py -f -c || echo "CVE update failed"
fi

# Download CPE dictionary if missing
CPE_FILE="CPE/official-cpe-dictionary_v2.3.xml"
if [ ! -f "$CPE_FILE" ]; then
    echo "Fetching CPE dictionary..."
    mkdir -p CPE
    cd CPE
    wget -q https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
    gunzip official-cpe-dictionary_v2.3.xml.gz
    cd ..
fi

exec uvicorn api:app --host 0.0.0.0 --port 8000