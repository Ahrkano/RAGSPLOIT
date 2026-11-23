# -*- coding: utf-8 -*-
"""
Teste de conectividade REAL multi-provider contra o proxy em execucao.

Para cada provedor (google/openai/anthropic) cuja chave esteja presente no
ambiente, faz um POST minimo ao proxy e verifica que volta uma completion
valida. Provedor sem chave e PULADO (SKIP), nunca falha. Faz tambem uma
checagem negativa: um provedor sem chave deve responder 500 citando a env var.

Gasta credito real nos provedores com chave. Uso:

    # de dentro do core (fala com o proxy pela rede do lab):
    docker exec -i core_orchestrator env PROXY_URL=http://192.168.70.40:8080 \
        python /app/src/test/test_proxy_live.py
    # ou de dentro do proxy:
    docker exec -i llm_proxy python /app/test_proxy_live.py

Variaveis: PROXY_URL (default http://localhost:8080).
"""
import os
import json
import sys
import urllib.request
import urllib.error

PROXY_URL = os.getenv("PROXY_URL", "http://localhost:8080").rstrip("/")

# Caminho do config do projeto (montado em /app/config nos containers).
AI_SETTINGS = os.getenv("AI_SETTINGS", "/app/config/ai_settings.json")


def _google_model(default="gemini/gemini-3-flash-preview"):
    """Usa o modelo Google configurado no projeto (evita defaults obsoletos)."""
    try:
        with open(AI_SETTINGS) as f:
            cfg = json.load(f)
        if cfg.get("provider") == "google" and str(cfg.get("model", "")).startswith("gemini/"):
            return cfg["model"]
    except Exception:
        pass
    return default


PROVIDERS = [
    ("google",    "GOOGLE_API_KEY",    _google_model()),
    ("openai",    "OPENAI_API_KEY",    "openai/gpt-4o-mini"),
    ("anthropic", "ANTHROPIC_API_KEY", "anthropic/claude-haiku-5-5"),
]

PROMPT = "Responda apenas com a palavra OK."


def _post(body, timeout=60):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{PROXY_URL}/chat/completions", data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {"error": "<corpo nao-JSON>"}
    except Exception as e:
        return None, {"error": str(e)}


def proxy_mode():
    try:
        with urllib.request.urlopen(f"{PROXY_URL}/health", timeout=5) as r:
            return json.loads(r.read().decode("utf-8")).get("mode")
    except Exception as e:
        return f"<inacessivel: {e}>"


def check_positive(provider, model):
    status, body = _post({
        "model": model,
        "messages": [{"role": "user", "content": PROMPT}],
        "temperature": 0,
        "max_tokens": 16,
    })
    if status == 200 and body.get("choices"):
        txt = body["choices"][0].get("message", {}).get("content", "")
        print(f"[PASS] {provider:9s} {model} -> {txt!r}")
        return True
    print(f"[FAIL] {provider:9s} {model} -> status={status} corpo={body}")
    return False


def check_negative(provider, model, env_var):
    status, body = _post({"model": model, "messages": [{"role": "user", "content": "x"}]})
    if status == 500 and env_var in str(body.get("error", "")):
        print(f"[PASS] {provider:9s} (sem chave) -> 500 citando {env_var}")
        return True
    print(f"[FAIL] {provider:9s} (sem chave) esperava 500/{env_var}, veio status={status} corpo={body}")
    return False


def main():
    print(f"=== TESTE LIVE MULTI-PROVIDER | proxy={PROXY_URL} ===")
    mode = proxy_mode()
    print(f"[*] /health mode = {mode}")
    if mode == "local":
        print("[SKIP-ALL] proxy em modo 'local' (tunel SSH): roteamento cloud desativado.")
        return 0
    if isinstance(mode, str) and mode.startswith("<inacessivel"):
        print("[ERRO] proxy inacessivel; verifique PROXY_URL e se o container esta de pe.")
        return 2

    results = []
    for provider, env_var, model in PROVIDERS:
        if os.getenv(env_var):
            results.append(check_positive(provider, model))
        else:
            print(f"[SKIP] {provider:9s} ({env_var} ausente)")
            results.append(check_negative(provider, model, env_var))

    tested = [r for r in results if r is not None]
    failed = tested.count(False)
    print(f"\n=== {tested.count(True)}/{len(tested)} OK, {failed} falha(s) ===")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
