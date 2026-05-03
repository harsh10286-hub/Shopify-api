FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache curl libcurl gcc musl-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Your file is main.py, not shopify_api.py
COPY main.py .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
