# Threat Detection

Este projeto reúne um backend em **FastAPI** e um frontend em **Next.js** para realizar varreduras de infraestrutura e correlacionar vulnerabilidades encontradas.

Abaixo segue um guia comentado para preparar um ambiente Debian do zero e executar a aplicação.

## Requisitos

- Debian atualizado
- Python 3.11
- Node.js 18
- Go (para compilar utilitários do ProjectDiscovery)
- MongoDB 7

## Passo a passo para instalar em um Debian limpo

### 1. Preparação inicial

```bash
apt-get install sudo
sudo apt-get update && sudo apt-get upgrade
```

### 2. Dependências de desenvolvimento

Instale Python 3.11 e pacotes necessários para compilar bibliotecas:

```bash
sudo apt-get install python3.11 python3.11-venv
sudo apt-get install build-essential
sudo apt-get install libpcap-dev
```

### 3. Instalação do Node.js 18

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### 4. Instalação do Go

```bash
cd /tmp
wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
```

### 5. Utilitários do ProjectDiscovery

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

### 6. Instalação do MongoDB 7

```bash
curl -fsSL https://pgp.mongodb.com/server-7.0.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg
echo "deb [ arch=amd64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/7.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update
sudo apt install -y mongodb-org
```

### 7. Clonar e configurar o projeto

```bash
git clone https://github.com/VictorEneias/threat-detection.git
cd threat-detection
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 8. Popular base CVE com cve-search

```bash
git clone https://github.com/cve-search/cve-search.git cve-db/cve-search
cd cve-db/cve-search
pip install -r requirements.txt
./sbin/db_updater.py -f -c
cd ../..
```

### 9. Baixar o dicionário CPE

```bash
mkdir -p CPE
cd CPE
wget https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
gunzip official-cpe-dictionary_v2.3.xml.gz
cd ..
```

### 10. Instalar dependências do frontend

```bash
cd frontend/threat-detection
npm install
```

## Como executar

Em um terminal, inicie o backend:

```bash
uvicorn api:app --reload
# ou
uvicorn api:app --host 0.0.0.0 --port 8000
```

Em outro terminal, do diretório `frontend/threat-detection`, inicie o frontend:

```bash
npm run dev
# ou
npm run dev -- -H 0.0.0.0 -p 3000
```

Com ambos os serviços rodando, a aplicação estará acessível para testes e uso.

Relatórios em PDF são criados automaticamente ao término de cada análise e podem ser baixados na área `/admin` do frontend. Nessa área também ficam disponíveis os chamados enviados pelos usuários via formulário de contato.

### Variáveis de ambiente

Algumas configurações podem ser ajustadas antes de iniciar o backend e o frontend:

- `FRONTEND_URL`: origem permitida pelo CORS (padrão: `http://localhost:3000`)
- `NEXT_PUBLIC_API_BASE`: URL do backend utilizada pelo frontend (padrão: `http://localhost:8000`)
- `NEXT_PUBLIC_APP_PASSWORD`: senha exigida na tela inicial do frontend (padrão: `senha`)

O servidor de desenvolvimento do Next.js roda apenas em HTTP. Caso deseje disponibilizar o frontend em HTTPS, utilize um proxy reverso (por exemplo, nginx) para fornecer o certificado TLS.

