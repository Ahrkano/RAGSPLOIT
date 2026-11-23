import os
import logging
import subprocess
import threading
import time
import requests
from flask import Flask, request, jsonify, Response
from litellm import completion

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("llm_proxy")

app = Flask(__name__)

# --- Configuracoes gerais ---
SSH_USER = os.getenv("SSH_USER")
SSH_PASS = os.getenv("SSH_PASS")
SSH_HOST = os.getenv("SSH_HOST")
SSH_PORT = os.getenv("SSH_PORT", "22")
LLM_TARGET = os.getenv("LLM_TARGET", "localhost:1234")
# 'local' (tunel SSH) ou um provedor cloud ('google' | 'openai' | 'anthropic').
# No modo cloud o provedor efetivo e decidido pelo prefixo do modelo recebido,
# com AI_PROVIDER servindo apenas de fallback.
AI_PROVIDER = os.getenv("AI_PROVIDER", "local")
LOCAL_TUNNEL_PORT = "5050"

# Robustez: timeout e retries das chamadas ao LLM (configuraveis via env).
COMPLETION_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "60"))
COMPLETION_RETRIES = int(os.getenv("LLM_NUM_RETRIES", "2"))

# Mapa provedor -> variavel de ambiente com a chave de API.
PROVIDER_ENV = {
    "google": "GOOGLE_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}

# Default por provedor quando o request nao especifica modelo.
PROVIDER_DEFAULT_MODEL = {
    "google": "gemini/gemini-1.5-flash",
    "openai": "openai/gpt-4o-mini",
    "anthropic": "anthropic/claude-opus-5-5",
}

# Parametros do protocolo OpenAI que repassamos ao LiteLLM.
PASSTHROUGH_PARAMS = {
    "temperature", "max_tokens", "top_p", "n", "stop",
    "presence_penalty", "frequency_penalty", "logit_bias",
    "response_format", "seed", "tools", "tool_choice", "user",
}


def detect_provider(model):
    """Deduz o provedor a partir do prefixo (ou nome) do modelo."""
    m = (model or "").lower()
    if m.startswith(("gemini/", "models/")):
        return "google"
    if m.startswith("openai/") or m.startswith("gpt") or m.startswith("o1") or m.startswith("o3"):
        return "openai"
    if m.startswith("anthropic/") or m.startswith("claude"):
        return "anthropic"
    return None


def start_ssh_tunnel():
    """Mantem o tunel SSH vivo em background (modo 'local')."""
    cmd = [
        "sshpass", "-p", SSH_PASS,
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=30",
        "-N", "-L", f"{LOCAL_TUNNEL_PORT}:{LLM_TARGET}",
        f"{SSH_USER}@{SSH_HOST}", "-p", SSH_PORT
    ]
    log.info("[TUNNEL] Iniciando tunel para %s...", SSH_HOST)
    while True:
        try:
            proc = subprocess.Popen(cmd)
            proc.wait()
            log.warning("[TUNNEL] Conexao caiu. Reconectando em 5s...")
            time.sleep(5)
        except Exception as e:
            log.error("[TUNNEL] Erro critico: %s", e)
            time.sleep(10)


def _serialize(response):
    """Serializacao blindada do objeto de resposta do LiteLLM."""
    if hasattr(response, 'model_dump_json'):
        return response.model_dump_json()
    if hasattr(response, 'json'):
        return response.json()
    import json
    return json.dumps(dict(response))


@app.route('/chat/completions', methods=['POST'])
@app.route('/v1/chat/completions', methods=['POST'])
def chat_proxy():
    data = request.json or {}
    model = data.get("model", "")

    # MODO LOCAL: encaminha para o tunel SSH.
    if AI_PROVIDER == "local":
        log.info("[PROXY] Roteando para Tunel Local...")
        try:
            target_url = f"http://127.0.0.1:{LOCAL_TUNNEL_PORT}/v1/chat/completions"
            resp = requests.post(
                target_url,
                json=data,
                headers={"Content-Type": "application/json"},
                timeout=COMPLETION_TIMEOUT,
            )
            return Response(resp.content, resp.status_code,
                            content_type=resp.headers.get('Content-Type', 'application/json'))
        except Exception as e:
            log.error("[PROXY] Falha no tunel local: %s", e)
            return jsonify({"error": f"Falha no tunel local: {str(e)}"}), 502

    # MODO CLOUD: roteamento unico via LiteLLM, por prefixo do modelo.
    provider = detect_provider(model) or AI_PROVIDER
    if provider not in PROVIDER_ENV:
        log.warning("[PROXY] Provedor nao suportado: %s (modelo %s)", provider, model)
        return jsonify({"error": f"Provedor nao suportado: '{provider}' (modelo '{model}')"}), 400

    env_var = PROVIDER_ENV[provider]
    api_key = os.getenv(env_var)
    if not api_key:
        log.error("[PROXY] %s ausente para provedor '%s'", env_var, provider)
        return jsonify({"error": f"{env_var} not set (provedor '{provider}')"}), 500

    if not model:
        model = PROVIDER_DEFAULT_MODEL[provider]

    log.info("[PROXY] Roteando para %s via LiteLLM | modelo: %s", provider.upper(), model)

    # Repassa o corpo completo (temperature, max_tokens, etc.), nao so model+messages.
    kwargs = {k: v for k, v in data.items() if k in PASSTHROUGH_PARAMS}
    kwargs["model"] = model
    kwargs["messages"] = data.get("messages", [])
    kwargs["api_key"] = api_key
    kwargs["timeout"] = COMPLETION_TIMEOUT
    kwargs["num_retries"] = COMPLETION_RETRIES

    try:
        response = completion(**kwargs)
        return Response(_serialize(response), mimetype='application/json')
    except Exception as e:
        log.error("[PROXY] Erro na completion (%s): %s", model, e)
        return jsonify({"error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "mode": AI_PROVIDER}), 200


def log_startup_state():
    log.info("=== LLM Proxy | modo: %s | timeout=%ss retries=%s ===",
             AI_PROVIDER.upper(), COMPLETION_TIMEOUT, COMPLETION_RETRIES)
    if AI_PROVIDER != "local":
        for prov, var in PROVIDER_ENV.items():
            status = "OK" if os.getenv(var) else "AUSENTE"
            log.info("[KEYS] %-9s (%s): %s", prov, var, status)


# No modo local iniciamos o tunel; nos modos cloud ele e desnecessario.
if AI_PROVIDER == "local":
    threading.Thread(target=start_ssh_tunnel, daemon=True).start()

log_startup_state()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
