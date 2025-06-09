# Threat Detection

This repository contains a FastAPI backend and a Next.js frontend used to scan
infrastructure and map vulnerabilities. The application relies on MongoDB and
external tools from ProjectDiscovery.

## Requirements

- Python 3.11 or newer
- Node.js 18+
- Go (to build ProjectDiscovery utilities)
- MongoDB running locally
- External tools available in `PATH`: `subfinder`, `dnsx`, `naabu`
- The file `CPE/official-cpe-dictionary_v2.3.xml` placed under `CPE/`

## Quick Installation

```bash
pip install -r requirements.txt
cd frontend/threat-detection && npm install
```

Ensure that `subfinder`, `dnsx`, `naabu` are available in your shell and that a
MongoDB instance is running.

## Full Setup on Debian

The steps below reproduce the development environment on a clean Debian
installation.

1. Update the system:
   ```bash
   sudo apt-get update && sudo apt-get upgrade
   ```
2. Install Python 3.11+ (from Debian repositories or a source like deadsnakes):
   ```bash
   sudo apt-get install python3.11 python3.11-venv
   ```
3. Install Node.js 18+
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```
4. Install Go (required for the external scanners)
   ```bash
   sudo apt-get install -y golang
   export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
   ```
5. Install external tools from ProjectDiscovery
   ```bash
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
   go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
   ```
6. Install MongoDB and enable the service
   ```bash
   wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
   echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/debian bullseye/mongodb-org/6.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
   sudo apt-get update
   sudo apt-get install -y mongodb-org
   sudo systemctl enable --now mongod
   ```
7. Populate CVE data using cve-search
   ```bash
   git clone https://github.com/cve-search/cve-search.git cve-db/cve-search
   cd cve-db/cve-search
   pip install -r requirements.txt
   python3 ./sbin/db_mgmt.py -p
   python3 ./sbin/create_indexes.py
   ```
8. Download the CPE dictionary
   ```bash
   mkdir -p CPE
   wget https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
   gunzip official-cpe-dictionary_v2.3.xml.gz
   mv official-cpe-dictionary_v2.3.xml CPE/
   ```
9. Install Python dependencies for this project
   ```bash
   cd /path/to/threat-detection
   pip install -r requirements.txt
   ```
10. Install frontend dependencies
   ```bash
   cd frontend/threat-detection
   npm install
   # optionally build: npm run build
   ```
11. Verify that the tools `subfinder`, `dnsx`, and `naabu` are in `PATH` and that
    MongoDB is running (`sudo systemctl status mongod`).

## Running

Start the backend:
```bash
uvicorn api:app --reload
```

In another terminal, run the frontend from `frontend/threat-detection`:
```bash
npm run dev
```

With the backend running you can POST an email to `/api/port-analysis` and later
fetch `/api/software-analysis/{job_id}` to obtain vulnerability data.

## Docker

You can build an image containing the backend:
```bash
docker build -t threat-detection .
docker run -p 8000:8000 threat-detection
```
Be sure to provide the external tools and CPE XML to the container or mount them
via a volume.
