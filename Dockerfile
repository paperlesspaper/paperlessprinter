FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./

# Fly will route HTTPS traffic to this internal port.
ENV IPP_LISTEN_HOST=0.0.0.0

CMD ["python", "server.py"]
