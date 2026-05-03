FROM python:3.11-alpine

WORKDIR /app

# Install libcurl and build tools (very small on Alpine)
RUN apk add --no-cache curl libcurl gcc musl-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shopify_api.py .

CMD ["uvicorn", "shopify_api:app", "--host", "0.0.0.0", "--port", "8000"]
