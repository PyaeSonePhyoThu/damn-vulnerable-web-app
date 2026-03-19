# VulnBank — Lab Setup Guide

> **FOR TRAINING USE ONLY. NEVER DEPLOY TO PRODUCTION OR PUBLIC NETWORKS.**

---

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose)
- Port **80** must be free on the host machine

---

## Start the Lab

```bash
git clone <repo-url>
cd damn-vulnerable-banking-web-app
docker compose up --build
```

Wait until you see:

```
backend_1  | * Running on http://0.0.0.0:8000
```

Then open **http://localhost** in your browser.

---

## Stop the Lab

```bash
docker compose down
```

To also wipe the database and start completely fresh:

```bash
docker compose down -v
docker compose up --build
```

**Port 80 already in use**

```bash
# Find what is using port 80
sudo lsof -i :80        # macOS / Linux
netstat -ano | findstr :80   # Windows

# Stop it, then retry
docker compose up --build
```

**Database errors on first run**

```bash
docker compose down -v
docker compose up --build
```

**Containers exit immediately**

```bash
docker compose logs backend
docker compose logs nginx
```
