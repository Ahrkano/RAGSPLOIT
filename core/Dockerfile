FROM python:3.10-slim
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"
RUN apt-get update && apt-get install -y build-essential curl nano wget sshuttle socat git iputils-ping && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY core/requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY config ./config
CMD ["sh", "-c", "python src/main_ingest.py || tail -f /dev/null"]
