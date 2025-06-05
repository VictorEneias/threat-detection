# Threat Detection

Este projeto possui um backend em Python (FastAPI) e um frontend em Next.js. Siga os passos abaixo para executar em qualquer servidor.

## Requisitos

- Python 3.11 ou superior
- Node.js 18+ para o frontend
- Ferramentas externas: `subfinder`, `dnsx`, `naabu` e um banco MongoDB em execução
- Arquivo `CPE/official-cpe-dictionary_v2.3.xml` para busca de CPE (não incluído no repositório)

## Instalação

1. Clone o repositório e instale as dependências Python:
   ```bash
   pip install -r requirements.txt
   ```
2. Instale as dependências do frontend:
   ```bash
   cd frontend/threat-detection
   npm install
   ```
3. (Opcional) Construa a aplicação para produção:
   ```bash
   npm run build
   ```
4. Certifique-se de que as ferramentas `subfinder`, `dnsx` e `naabu` estejam disponíveis no `PATH` do sistema e que o MongoDB esteja acessível.

## Executando

Para iniciar o backend durante o desenvolvimento:
```bash
uvicorn api:app --reload
```

O frontend pode ser iniciado em outro terminal usando:
```bash
npm run dev
```
no diretório `frontend/threat-detection`.

## Docker

Se preferir, é possível executar apenas o backend usando Docker:
```bash
docker build -t threat-detection .
docker run -p 8000:8000 threat-detection
```
Certifique-se de disponibilizar as dependências externas (ferramentas e CPE XML) no container ou via volume.

