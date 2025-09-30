# ---------- Stage 1: Builder ----------
FROM python:3.11-slim AS build

# Set working directory
WORKDIR /app

# Install build dependencies (for compiling wheels)
#RUN apt-get update && apt-get install -y --no-install-recommends \
#    build-essential gcc \
#    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

#------------------Stage 2: Run-----------
FROM python:3.11-slim

WORKDIR /app

COPY --from=build /install /usr/local

COPY . .

EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]



