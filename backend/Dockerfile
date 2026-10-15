FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip==26.2.1 && pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --uid 10001 --create-home sentinel
USER sentinel
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
