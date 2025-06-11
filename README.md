# Threat Detection

Este projeto reúne um backend em **FastAPI** e um frontend.\
Há duas opções de interface web: uma versão estática pronta para ser servida por nginx ou apache e o frontend original em **Next.js** (útil para desenvolvimento).

Abaixo segue um guia comentado para preparar um ambiente Debian do zero e executar a aplicação.

## Requisitos

- Debian atualizado
- Python 3.11
- Node.js 18 *(apenas se desejar utilizar o frontend Next.js)*
- Servidor web (nginx ou apache) para hospedar o frontend estático
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

### 3. (Opcional) Instalação do Node.js 18

Necessário apenas se desejar utilizar o frontend em Next.js.

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

### 10. Configurar o frontend estático

Não há dependências a instalar. Copie o conteúdo da pasta `frontend-static`
para o diretório servido pelo seu servidor web (por exemplo
`/var/www/threat-detection`). O arquivo `config.js` permite ajustar a URL do
backend (`API_BASE`) e a senha da aplicação (`APP_PASSWORD`).

## Como executar

Em um terminal, inicie o backend:

```bash
uvicorn api:app --reload
# ou
uvicorn api:app --host 0.0.0.0 --port 8000
```

Em outro terminal (ou serviço), sirva o conteúdo da pasta
`frontend-static` em seu servidor web. Caso utilize nginx, a diretiva
`root` deve apontar para esse diretório. Após iniciar o servidor,
acesse a página `index.html` pelo navegador.

Com o backend e o servidor web ativos, a aplicação estará acessível para testes
e uso.

### Variáveis de ambiente

Algumas configurações podem ser ajustadas antes de iniciar o backend e o frontend:

- `FRONTEND_URL`: origem permitida pelo CORS (padrão: `http://localhost`)
- Edite `frontend-static/config.js` para definir `API_BASE` (URL do backend) e `APP_PASSWORD`.

Para disponibilizar o frontend em HTTPS, configure seu servidor web (nginx ou apache) com um certificado TLS válido, por exemplo utilizando o Let's Encrypt.

