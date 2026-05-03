FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for curl_cffi
RUN apt-get update && apt-get install -y \
    curl \
    libcurl4-openssl-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shopify_api.py .

CMD ["uvicorn", "shopify_api:app", "--host", "0.0.0.0", "--port", "8000"]
