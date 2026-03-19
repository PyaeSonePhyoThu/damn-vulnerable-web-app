FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    git libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf2.0-0 \
    libffi-dev shared-mime-info && rm -rf /var/lib/apt/lists/*

WORKDIR /app/backend
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app
RUN mkdir -p /app/backend/uploads /app/backend/data

WORKDIR /app
# Init git repo so /.git/ exists for VD-1
RUN git init && \
    git config user.email "dev@vulnbank.local" && \
    git config user.name "VulnBank Dev" && \
    git add -A && \
    git commit -m "Initial commit - banking application" && \
    git commit --allow-empty -m "hotfix: remove hardcoded JWT secret"

WORKDIR /app/backend
CMD ["python", "app.py"]
