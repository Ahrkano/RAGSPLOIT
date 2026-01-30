FROM python:3.10-slim

# Instala ferramentas de sistema e SSH
RUN apt-get update && apt-get install -y \
    openssh-client \
    sshpass \
    iputils-ping \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala Flask, LiteLLM (para Google) e Requests
RUN pip install flask requests litellm google-generativeai

COPY hybrid_proxy.py /app/hybrid_proxy.py

CMD ["python", "/app/hybrid_proxy.py"]
