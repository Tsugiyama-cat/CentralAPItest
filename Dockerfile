FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY verify_api.py .
COPY stream_test.py .
COPY debug_payload.py .
COPY decoders.py .
COPY syslog_server.py .
COPY web_stream.py .
COPY templates/ templates/

CMD ["python", "verify_api.py"]
