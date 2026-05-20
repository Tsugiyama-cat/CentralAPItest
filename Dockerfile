FROM python:3.12-slim

WORKDIR /app

# Install only what we need
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY verify_api.py .

CMD ["python", "verify_api.py"]
