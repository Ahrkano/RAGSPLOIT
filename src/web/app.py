# -*- coding: utf-8 -*-
"""
RAGSPLOIT Web UI — servidor Flask + WebSocket(PTY) para operar a ferramenta
pelo navegador com menus interativos.

Funcionalidades:
  - Config: escolher provedor/modelo (reusa src/model_selector) e alvo.
  - Run: dispara o pipeline autonomo num PTY; a mesma janela de terminal
         (xterm.js) mostra o output ao vivo E permite digitar no shell
         interativo pos-exploracao.
  - Reports: lista os relatorios .txt e (re)gera/serve o relatorio HTML.

SEGURANCA (ferramenta ofensiva):
  - Deve escutar apenas em rede do lab / 127.0.0.1 (ver docker-compose: o
    publish e 127.0.0.1:PORT, nunca 0.0.0.0 publico).
  - Auth basica HTTP (WEBUI_USER / WEBUI_PASS).
  - O WebSocket usa um token efemero (gerado no boot e injetado nas paginas
    ja autenticadas), evitando depender de credenciais no handshake WS.
"""
import os
import sys
import json
import glob
import hmac
import signal
import select
import secrets
import threading
import subprocess
from functools import wraps

import pty
import struct
import fcntl
import termios

from flask import Flask, request, Response, render_template, jsonify, send_file, abort
from flask_sock import Sock

# --- PATHS e imports do projeto ---
BASE = "/app"
SRC = os.path.join(BASE, "src")
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from src import model_selector as ms          # noqa: E402
from src.pipeline_common import resolve_target, save_target, DEFAULT_TARGET  # noqa: E402

LOGS_DIR = "/app/data/logs"
REPORT_FILE = "/app/data/pentest_report.html"
GENERATE_REPORT = os.path.join(SRC, "generate_report.py")

# Pipelines de alvo unico que aceitam --target (allowlist — nunca executamos
# caminho arbitrario vindo do cliente).
ALLOWED_PIPELINES = {
    "pipe_v4.py": "Single Target (autonomo + shell interativo)",
    "pipe_rag_onoff.py": "Single Target (RAG on/off)",
}

# --- AUTH ---
WEBUI_USER = os.getenv("WEBUI_USER", "admin")
WEBUI_PASS = os.getenv("WEBUI_PASS", "ragsploit")
# Token efemero para o WebSocket (renovado a cada boot do processo).
WS_TOKEN = secrets.token_urlsafe(24)

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))
sock = Sock(app)


def _check_basic_auth(auth):
    if not auth:
        return False
    return (hmac.compare_digest(auth.username or "", WEBUI_USER)
            and hmac.compare_digest(auth.password or "", WEBUI_PASS))


@app.before_request
def _enforce_auth():
    # Rotas isentas: health (para healthcheck) e o WS (valida token proprio).
    if request.path == "/health" or request.path.startswith("/ws/"):
        return None
    if not _check_basic_auth(request.authorization):
        return Response(
            "Autenticacao necessaria.", 401,
            {"WWW-Authenticate": 'Basic realm="RAGSPLOIT"'},
        )
    return None


# --- Estado / helpers de config ---
def current_state():
    ms.load_dot_env()
    conf = ms.load_current_config()
    provider = conf.get("provider", "google")
    model = conf.get("model", "")
    keys = {p: bool(ms.get_provider_key(p)) for p in ms.PROVIDERS}
    return {
        "provider": provider,
        "model": model,
        "model_short": model.split("/", 1)[-1] if model else "",
        "target": resolve_target(None),
        "default_target": DEFAULT_TARGET,
        "providers": list(ms.PROVIDERS.keys()),
        "keys": keys,
        "temperature": conf.get("temperature", 0.1),
        "max_tokens": conf.get("max_tokens", 2000),
    }


# --- Paginas ---
@app.route("/")
def index():
    return render_template("index.html", st=current_state())


@app.route("/config")
def config_page():
    return render_template("config.html", st=current_state())


@app.route("/run")
def run_page():
    return render_template(
        "run.html", st=current_state(),
        pipelines=ALLOWED_PIPELINES, ws_token=WS_TOKEN,
    )


@app.route("/reports")
def reports_page():
    logs = _list_logs()
    return render_template(
        "reports.html", st=current_state(), logs=logs,
        has_html=os.path.exists(REPORT_FILE),
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


# --- API: modelos e configuracao ---
@app.route("/api/models")
def api_models():
    provider = request.args.get("provider", "google")
    if provider not in ms.PROVIDERS:
        return jsonify({"error": "provedor invalido"}), 400
    ms.load_dot_env()
    key = ms.get_provider_key(provider)
    if not key:
        return jsonify({"error": f"chave ausente para '{provider}'",
                        "env": ms.PROVIDERS[provider]["env"], "models": []}), 200
    models = ms.FETCHERS[provider](key)
    return jsonify({"provider": provider, "models": models}), 200


@app.route("/api/config", methods=["POST"])
def api_config():
    data = request.get_json(silent=True) or {}
    action = data.get("action")

    if action == "set_key":
        provider = data.get("provider")
        key = (data.get("api_key") or "").strip()
        if provider not in ms.PROVIDERS or not key:
            return jsonify({"error": "provedor/chave invalidos"}), 400
        ok = ms.update_env_file(ms.PROVIDERS[provider]["env"], key)
        return jsonify({"ok": ok}), (200 if ok else 500)

    if action == "set_model":
        provider = data.get("provider")
        model = (data.get("model") or "").strip()
        if provider not in ms.PROVIDERS or not model:
            return jsonify({"error": "provedor/modelo invalidos"}), 400
        ok, msg = ms.save_config(provider, model)
        return jsonify({"ok": ok, "model": msg}), (200 if ok else 500)

    if action == "set_target":
        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"error": "alvo vazio"}), 400
        try:
            save_target(target)
            return jsonify({"ok": True, "target": target}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "acao desconhecida"}), 400


# --- API: relatorios ---
def _list_logs():
    if not os.path.isdir(LOGS_DIR):
        return []
    files = sorted(glob.glob(os.path.join(LOGS_DIR, "*.txt")),
                   key=os.path.getmtime, reverse=True)
    out = []
    for f in files:
        out.append({
            "name": os.path.basename(f),
            "size": os.path.getsize(f),
            "mtime": int(os.path.getmtime(f)),
        })
    return out


def _safe_log_path(name):
    # Impede path traversal: apenas basename dentro de LOGS_DIR.
    name = os.path.basename(name)
    path = os.path.join(LOGS_DIR, name)
    if not path.startswith(os.path.abspath(LOGS_DIR) + os.sep):
        return None
    return path if os.path.isfile(path) else None


@app.route("/api/report/raw")
def api_report_raw():
    name = request.args.get("name", "")
    path = _safe_log_path(name)
    if not path:
        abort(404)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return Response(f.read(), mimetype="text/plain; charset=utf-8")


@app.route("/api/report/generate", methods=["POST"])
def api_report_generate():
    try:
        r = subprocess.run([sys.executable, GENERATE_REPORT],
                           capture_output=True, text=True, cwd=BASE,
                           env=os.environ.copy(), timeout=60)
        ok = (r.returncode == 0 and os.path.exists(REPORT_FILE))
        return jsonify({"ok": ok, "stdout": r.stdout[-2000:],
                        "stderr": r.stderr[-2000:]}), (200 if ok else 500)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/report.html")
def report_html():
    if not os.path.exists(REPORT_FILE):
        abort(404)
    return send_file(REPORT_FILE, mimetype="text/html")


# --- WebSocket: PTY do pipeline ---
@sock.route("/ws/run")
def ws_run(ws):
    # Valida token efemero (as paginas autenticadas o injetam).
    if not hmac.compare_digest(request.args.get("token", ""), WS_TOKEN):
        ws.send("\r\n[ERRO] token invalido. Recarregue a pagina autenticada.\r\n")
        return

    init = ws.receive()
    try:
        cfg = json.loads(init) if init else {}
    except Exception:
        cfg = {}

    pipeline = cfg.get("pipeline", "pipe_v4.py")
    if pipeline not in ALLOWED_PIPELINES:
        ws.send(f"\r\n[ERRO] pipeline nao permitido: {pipeline}\r\n")
        return

    target = resolve_target((cfg.get("target") or "").strip() or None)
    extra = []
    if cfg.get("disable_rag") and pipeline == "pipe_rag_onoff.py":
        extra.append("--disable-rag")

    argv = [sys.executable, os.path.join(SRC, pipeline), "--target", target] + extra

    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(
            argv, stdin=slave, stdout=slave, stderr=slave,
            cwd=BASE, env=os.environ.copy(),
            close_fds=True, preexec_fn=os.setsid,
        )
    except Exception as e:
        os.close(master)
        os.close(slave)
        ws.send(f"\r\n[ERRO] falha ao iniciar: {e}\r\n")
        return
    os.close(slave)

    ws.send(f"\r\n\033[92m>>> RAGSPLOIT :: {pipeline} --target {target} "
            f"{' '.join(extra)}\033[0m\r\n")

    send_lock = threading.Lock()
    stop = threading.Event()

    def pump_pty_to_ws():
        while not stop.is_set():
            try:
                r, _, _ = select.select([master], [], [], 0.2)
            except (OSError, ValueError):
                break
            if master in r:
                try:
                    data = os.read(master, 4096)
                except OSError:
                    break
                if not data:
                    break
                with send_lock:
                    try:
                        ws.send(data.decode(errors="ignore"))
                    except Exception:
                        break
        stop.set()

    reader = threading.Thread(target=pump_pty_to_ws, daemon=True)
    reader.start()

    try:
        while not stop.is_set():
            msg = ws.receive(timeout=1)
            if msg is None:
                if proc.poll() is not None:   # processo terminou
                    break
                continue
            # Mensagem de controle: redimensionamento do terminal.
            if msg.startswith('{') and '"resize"' in msg:
                try:
                    dims = json.loads(msg)["resize"]
                    fcntl.ioctl(master, termios.TIOCSWINSZ,
                                struct.pack("HHHH", dims["rows"], dims["cols"], 0, 0))
                    continue
                except Exception:
                    pass
            try:
                os.write(master, msg.encode())
            except OSError:
                break
    finally:
        stop.set()
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        try:
            os.close(master)
        except Exception:
            pass
        with send_lock:
            try:
                ws.send("\r\n\033[93m>>> Sessao encerrada.\033[0m\r\n")
            except Exception:
                pass


if __name__ == "__main__":
    port = int(os.getenv("WEBUI_PORT", "8090"))
    print(f"[WEBUI] RAGSPLOIT Web UI em 0.0.0.0:{port} (publish restrito no compose)")
    print(f"[WEBUI] user={WEBUI_USER}  (senha via WEBUI_PASS)")
    app.run(host="0.0.0.0", port=port, threaded=True)
