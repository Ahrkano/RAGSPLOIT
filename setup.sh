#!/bin/sh

# ==============================================================================
# 1. ESTRUTURA DE DIRETÓRIOS
# ==============================================================================
echo "[*] Recriando estrutura do laboratório..."
mkdir -p lab-security
cd lab-security
mkdir -p core src config/ingest data/vectorstore atk tgt llm_proxy

# ==============================================================================
# 2. CORE (MANTIDO IGUAL)
# ==============================================================================
cat <<EOF > config/settings.py
import os
import torch
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "config", "ingest") 
VECTORSTORE_PATH = os.getenv("CHROMA_PERSIST_DIR", os.path.join(BASE_DIR, "data", "vectorstore"))
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
LAB_LLM_URL = os.getenv("LAB_LLM_URL", "http://localhost:8080/v1")
EOF

echo "Metasploit Framework: Ferramenta de teste." > config/ingest/kb_metasploit.txt

cat <<EOF > core/Dockerfile
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
EOF

cat <<EOF > core/requirements.txt
langchain==0.3.0
langchain-community==0.3.0
langchain-core==0.3.0
langchain-openai==0.2.0
langchain-huggingface==0.1.0
langchain-chroma==0.1.4
chromadb==0.5.3
sentence-transformers==3.1.1
torch
pymetasploit3==1.0.3
python-dotenv==1.0.1
requests
EOF

# ==============================================================================
# 3. NOVO LLM PROXY HÍBRIDO (PYTHON + LITELLM + SSH)
# ==============================================================================

# Script Híbrido: Gerencia o Túnel e a API do Google
cat <<EOF > llm_proxy/hybrid_proxy.py
import os
import subprocess
import threading
import time
import requests
from flask import Flask, request, jsonify, Response
from litellm import completion

app = Flask(__name__)

# Configurações
SSH_USER = os.getenv("SSH_USER")
SSH_PASS = os.getenv("SSH_PASS")
SSH_HOST = os.getenv("SSH_HOST")
SSH_PORT = os.getenv("SSH_PORT", "22")
LLM_TARGET = os.getenv("LLM_TARGET", "localhost:1234")
AI_PROVIDER = os.getenv("AI_PROVIDER", "local") # 'local' ou 'google'
LOCAL_TUNNEL_PORT = "5050"

def start_ssh_tunnel():
    """Mantém o túnel SSH vivo em background"""
    cmd = [
        "sshpass", "-p", SSH_PASS,
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=30",
        "-N", "-L", f"{LOCAL_TUNNEL_PORT}:{LLM_TARGET}",
        f"{SSH_USER}@{SSH_HOST}", "-p", SSH_PORT
    ]
    
    print(f"[TUNNEL] Iniciando túnel para {SSH_HOST}...")
    while True:
        try:
            # Roda o SSH. Se cair, o processo termina e o loop reinicia.
            proc = subprocess.Popen(cmd)
            proc.wait()
            print("[TUNNEL] Conexão caiu. Reconectando em 5s...")
            time.sleep(5)
        except Exception as e:
            print(f"[TUNNEL] Erro crítico: {e}")
            time.sleep(10)

@app.route('/chat/completions', methods=['POST'])
def chat_proxy():
    data = request.json
    
    # MODO 1: Google Gemini (Via LiteLLM)
    if AI_PROVIDER == "google":
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            return jsonify({"error": "GOOGLE_API_KEY not set"}), 500
            
        print("[PROXY] Roteando para Google Gemini...")
        try:
            # LiteLLM traduz o formato OpenAI (data['messages']) para Gemini
            response = completion(
                model="gemini/gemini-1.5-flash", 
                messages=data.get("messages", []),
                api_key=api_key
            )
            # Retorna a resposta no formato OpenAI
            return jsonify(response)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # MODO 2: Local (Via Túnel SSH)
    else:
        print("[PROXY] Roteando para Túnel Local...")
        try:
            # Encaminha para a porta do túnel (5050)
            target_url = f"http://127.0.0.1:{LOCAL_TUNNEL_PORT}/v1/chat/completions"
            # Alguns backends locais não usam /v1, ajustar conforme necessário
            
            resp = requests.post(
                target_url, 
                json=data,
                headers={"Content-Type": "application/json"}
            )
            return Response(resp.content, resp.status_code, content_type=resp.headers['Content-Type'])
        except Exception as e:
            return jsonify({"error": f"Falha no túnel local: {str(e)}"}), 502

# Inicia o túnel apenas se o modo for local, ou sempre (opcional)
# Aqui iniciamos sempre para permitir troca rápida via env var se reiniciarmos
threading.Thread(target=start_ssh_tunnel, daemon=True).start()

if __name__ == '__main__':
    print(f"[PROXY] Iniciando servidor híbrido. Modo atual: {AI_PROVIDER.upper()}")
    app.run(host='0.0.0.0', port=8080)
EOF

# Dockerfile atualizado com dependências do LiteLLM
cat <<EOF > llm_proxy/Dockerfile
FROM python:3.10-slim

# Instala ferramentas de sistema e SSH
RUN apt-get update && apt-get install -y \\
    openssh-client \\
    sshpass \\
    iputils-ping \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala Flask, LiteLLM (para Google) e Requests
RUN pip install flask requests litellm google-generativeai

COPY hybrid_proxy.py /app/hybrid_proxy.py

CMD ["python", "/app/hybrid_proxy.py"]
EOF

# ==============================================================================
# 4. DEMAIS SERVIÇOS
# ==============================================================================
cat <<EOF > atk/Dockerfile
FROM metasploitframework/metasploit-framework:latest
WORKDIR /usr/src/metasploit-framework
EXPOSE 55553
ENTRYPOINT ["sh", "-c"]
CMD ["bundle exec ruby msfrpcd -f -S -U msf -P msfpass -a 0.0.0.0 -p 55553"]
EOF

cat <<EOF > tgt/Dockerfile
FROM tleemcjr/metasploitable2
EOF

# ==============================================================================
# 5. ORQUESTRAÇÃO
# ==============================================================================

# .env atualizado com chaves do Google e Seletor
cat <<EOF > .env
# Configurações Gerais
LAB_LLM_URL=http://192.168.70.40:8080
NVD_API_KEY=NVD_KEY

# --- SELETOR DE INTELIGÊNCIA ---
# Use 'google' para Gemini ou 'local' para o Túnel SSH
AI_PROVIDER=local

# --- CREDENCIAIS GOOGLE ---
GOOGLE_API_KEY=GEMINI_KEY

# --- CREDENCIAIS LOCAL (SSH) ---
LLM_TARGET=localhost:1234
SSH_HOST=192.168.1.100
SSH_PORT=22
SSH_USER=usuario
SSH_PASS=senha
EOF

cat <<EOF > docker-compose.yml
version: '3.8'

networks:
  llm-rag_labnet:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.70.0/24

services:
  core:
    build: 
      context: .
      dockerfile: ./core/Dockerfile
    container_name: core_orchestrator
    tty: true
    stdin_open: true
    depends_on:
      - atk
      - tgt
      - localai-proxy
    networks:
      llm-rag_labnet:
        ipv4_address: 192.168.70.10
    volumes:
      - ./data/vectorstore:/app/data
      - ./src:/app/src
      - ./config:/app/config
    environment:
      LAB_LLM_URL: \${LAB_LLM_URL}
      CHROMA_PERSIST_DIR: /app/data
      ATK_RPC_URL: http://192.168.70.20:55553
      NVD_API_KEY: \${NVD_API_KEY}
      AUTO_INGEST: "false"
    extra_hosts:
      - "host.docker.internal:host-gateway"

  atk:
    build: ./atk
    container_name: metasploit_atk
    networks:
      llm-rag_labnet:
        ipv4_address: 192.168.70.20
    ports:
      - "55553:55553"

  tgt:
    build: ./tgt
    container_name: vulnerable_tgt
    tty: true 
    networks:
      llm-rag_labnet:
        ipv4_address: 192.168.70.30
    ports:
      - "8081:80"   
      - "2121:21"   
      - "2222:22"   
      - "2323:23"   

  localai-proxy:
    build: ./llm_proxy
    container_name: llm_proxy
    networks:
      llm-rag_labnet:
        ipv4_address: 192.168.70.40
    env_file:
      - .env
EOF

echo "[SUCESSO] Lab configurado!"
echo "1. Edite o arquivo lab-security/.env para escolher o modo (Google/LocalAI) e colocar as credenciais."
echo "2. Para rodar: cd lab-security && docker-compose up -d --build"