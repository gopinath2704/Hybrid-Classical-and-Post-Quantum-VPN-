# Deployment & Execution Guide

## Prerequisites
- Docker & Docker Compose (or WSL2 with Linux `NET_ADMIN` capabilities)
- Python 3.10+
- OpenSSL & `liboqs` installed

## Running with Docker Compose
```bash
docker-compose up --build
```

## Running Application Dashboard
```bash
uvicorn app.backend.api:app --reload --port 8000
```
Open `http://localhost:8000` in browser to view the application UI.
