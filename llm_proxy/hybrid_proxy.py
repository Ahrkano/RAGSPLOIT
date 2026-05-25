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
                model=data.get("model", "gemini/gemini-pro"), 
                messages=data.get("messages", []),
                api_key=api_key
            )
            # --- SERIALIZAÇÃO BLINDADA ---
            if hasattr(response, 'model_dump_json'):
                json_str = response.model_dump_json()
            elif hasattr(response, 'json'):
                json_str = response.json()
            else:
                import json
                json_str = json.dumps(dict(response))
                
            return Response(json_str, mimetype='application/json')
            # -----------------------------
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