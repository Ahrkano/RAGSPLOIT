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
  - Login por sessao (pagina /login; cookie assinado). Credenciais em
    WEBUI_USER / WEBUI_PASS; chave do cookie em WEBUI_SECRET_KEY (opcional).
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

from datetime import timedelta

from flask import (Flask, request, Response, render_template, jsonify,
                   send_file, abort, session, redirect, url_for)
from flask_sock import Sock

# --- PATHS e imports do projeto ---
BASE = "/app"
SRC = os.path.join(BASE, "src")
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from src import model_selector as ms          # noqa: E402
from src.pipeline_common import resolve_target, save_target, DEFAULT_TARGET  # noqa: E402
from src import cve_scheduler                   # noqa: E402
from src import cve_sources                      # noqa: E402
from src import wordlists                         # noqa: E402

LOGS_DIR = "/app/data/logs"
REPORT_FILE = "/app/data/pentest_report.html"
GENERATE_REPORT = os.path.join(SRC, "generate_report.py")
RAG_ADMIN = os.path.join(SRC, "rag_admin.py")
VSTORE = os.getenv("CHROMA_PERSIST_DIR", "/app/data")
CVE_FILE = "/app/config/ingest/kb_recent_threats.txt"
CVE_STATE = os.path.join(LOGS_DIR, "cve_last_update.json")

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
# Duracao da sessao autenticada (cookie assinado).
SESSION_HOURS = float(os.getenv("WEBUI_SESSION_HOURS", "8"))

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))
# Chave para assinar o cookie de sessao. Se WEBUI_SECRET_KEY nao for definida,
# gera uma por boot (reinicios do processo deslogam todos — aceitavel no lab).
app.secret_key = os.getenv("WEBUI_SECRET_KEY") or secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(hours=SESSION_HOURS)
sock = Sock(app)

# Operacoes de base de conhecimento (reset/update) podem demorar (ingestao +
# embeddings), entao rodam numa thread unica de background.
_JOB = {"running": False, "name": None, "result": None, "started": None, "finished": None}
_JOB_LOCK = threading.Lock()


def _run_job(name, fn):
    with _JOB_LOCK:
        if _JOB["running"]:
            return False
        _JOB.update(running=True, name=name, result=None,
                    started=datetime_now(), finished=None)

    def worker():
        try:
            res = fn()
        except Exception as e:
            res = {"ok": False, "error": str(e)}
        with _JOB_LOCK:
            _JOB.update(running=False, result=res, finished=datetime_now())

    threading.Thread(target=worker, daemon=True, name=f"job-{name}").start()
    return True


def datetime_now():
    import datetime as _d
    return _d.datetime.now().isoformat(timespec="seconds")


def _rag_cli(args, timeout=1800):
    """Executa src/rag_admin.py em SUBPROCESSO e devolve o JSON-marcador.

    Toda interacao com o ChromaDB acontece em processo separado: o ChromaDB
    e singleton por processo e o langchain_chroma colide com qualquer outro
    client aberto no mesmo processo (ex.: o da Web UI). O subprocesso isola isso.
    """
    try:
        r = subprocess.run([sys.executable, RAG_ADMIN] + args, cwd=BASE,
                           env=os.environ.copy(), capture_output=True,
                           text=True, timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    for line in reversed((r.stdout or "").splitlines()):
        if line.startswith("RAGADMIN_JSON:"):
            try:
                return json.loads(line[len("RAGADMIN_JSON:"):])
            except Exception:
                break
    return {"ok": r.returncode == 0, "stderr": (r.stderr or "")[-500:],
            "stdout_tail": (r.stdout or "")[-500:]}


def _light_stats():
    """Stats sem abrir o ChromaDB (usado enquanto um job esta rodando)."""
    emb_dir = os.path.join(VSTORE, "emb_cache")
    try:
        emb = len(os.listdir(emb_dir)) if os.path.isdir(emb_dir) else 0
    except Exception:
        emb = -1
    state = {}
    try:
        with open(CVE_STATE) as f:
            state = json.load(f)
    except Exception:
        pass
    return {
        "doc_count": "(ocupado)",
        "emb_cache_entries": emb,
        "cve_file_exists": os.path.exists(CVE_FILE),
        "cve_file_mtime": (int(os.path.getmtime(CVE_FILE))
                           if os.path.exists(CVE_FILE) else None),
        "last_cve_update": state.get("last_cve_update"),
        "last_reset": state.get("last_reset"),
    }


def _credentials_ok(user, pw):
    return (hmac.compare_digest(user or "", WEBUI_USER)
            and hmac.compare_digest(pw or "", WEBUI_PASS))


def _safe_next(nxt):
    """Evita open-redirect: so aceita caminho local (uma barra inicial)."""
    if nxt and nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return "/"


@app.before_request
def _enforce_auth():
    p = request.path
    # Rotas isentas: pagina de login, health (healthcheck) e o WS (valida
    # token proprio). Assets estaticos tambem ficam liberados.
    if (p == "/login" or p == "/health"
            or p.startswith("/ws/") or p.startswith("/static/")):
        return None
    if session.get("auth"):
        return None
    # Chamadas de API respondem 401 (o front trata); paginas vao ao /login.
    if p.startswith("/api/"):
        return jsonify({"error": "nao autenticado"}), 401
    return redirect(url_for("login", next=p))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        nxt = _safe_next(request.form.get("next") or request.args.get("next"))
        if _credentials_ok(user, pw):
            session.clear()
            session.permanent = True
            session["auth"] = True
            session["user"] = WEBUI_USER
            return redirect(nxt)
        return render_template("login.html",
                               error="Acesso negado: credenciais invalidas.",
                               next=nxt), 401
    if session.get("auth"):
        return redirect("/")
    return render_template("login.html", error=None,
                           next=_safe_next(request.args.get("next")))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Estado / helpers de config ---
def current_state():
    ms.load_dot_env()
    conf = ms.load_current_config()
    provider = conf.get("provider", "google")
    model = conf.get("model", "")
    # NB: a chave deste dict NAO pode se chamar "keys" — no Jinja, {{ st.keys }}
    # resolve para o metodo dict.keys, nao para o item. Usamos "provider_keys".
    provider_keys = {p: bool(ms.get_provider_key(p)) for p in ms.PROVIDERS}
    return {
        "provider": provider,
        "model": model,
        "model_short": model.split("/", 1)[-1] if model else "",
        "target": resolve_target(None),
        "default_target": DEFAULT_TARGET,
        "providers": list(ms.PROVIDERS.keys()),
        "provider_keys": provider_keys,
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


@app.route("/knowledge")
def knowledge_page():
    return render_template("knowledge.html", st=current_state())


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


# --- API: base de conhecimento (RAG / CVE) e telemetria LLM ---
@app.route("/api/rag/stats")
def api_rag_stats():
    with _JOB_LOCK:
        running = _JOB["running"]
        job = {k: _JOB[k] for k in ("running", "name", "started", "finished", "result")}
    # Enquanto um job roda, nao abrir o ChromaDB (evita lock concorrente).
    stats = _light_stats() if running else _rag_cli(["stats"], timeout=60)
    return jsonify({"stats": stats, "job": job}), 200


@app.route("/api/cve/update", methods=["POST"])
def api_cve_update():
    started = _run_job("update-cves", lambda: _rag_cli(["update-cves"], timeout=300))
    return jsonify({"started": started,
                    "msg": "atualizacao de CVEs iniciada" if started
                    else "ja existe uma operacao em andamento"}), (202 if started else 409)


@app.route("/api/rag/reset", methods=["POST"])
def api_rag_reset():
    data = request.get_json(silent=True) or {}
    args = ["reset"] if data.get("fetch_cves", True) else ["reset", "--no-cves"]
    started = _run_job("reset", lambda: _rag_cli(args, timeout=1800))
    return jsonify({"started": started,
                    "msg": "reset do RAG iniciado" if started
                    else "ja existe uma operacao em andamento"}), (202 if started else 409)


@app.route("/api/cve/sources")
def api_cve_sources():
    return jsonify({"sources": cve_sources.status()}), 200


@app.route("/api/cve/sources", methods=["POST"])
def api_cve_sources_update():
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    cfg = cve_sources.load_sources()
    sid = data.get("source")
    if sid not in cfg:
        return jsonify({"error": "fonte desconhecida"}), 400
    if action == "toggle":
        cfg[sid]["enabled"] = bool(data.get("enabled"))
        cve_sources.save_sources(cfg)
        return jsonify({"ok": True, "enabled": cfg[sid]["enabled"]}), 200
    if action == "set_key":
        env = (cfg[sid].get("api") or {}).get("env")
        key = (data.get("api_key") or "").strip()
        if not env:
            return jsonify({"error": "esta fonte nao usa chave de API"}), 400
        if not key:
            return jsonify({"error": "chave vazia"}), 400
        ok = ms.update_env_file(env, key)
        return jsonify({"ok": ok}), (200 if ok else 500)
    return jsonify({"error": "acao desconhecida"}), 400


@app.route("/api/wordlists")
def api_wordlists():
    return jsonify({"wordlists": wordlists.list_wordlists()}), 200


@app.route("/api/wordlists", methods=["POST"])
def api_wordlists_add():
    if "file" in request.files:
        f = request.files["file"]
        name, data = f.filename, f.read()
    else:
        j = request.get_json(silent=True) or {}
        name, data = j.get("name"), j.get("content", "")
    if not name or not data:
        return jsonify({"error": "arquivo/nome ausente"}), 400
    try:
        info = wordlists.add_wordlist(name, data)
        return jsonify({"ok": True, "wordlist": info}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/wordlists/delete", methods=["POST"])
def api_wordlists_delete():
    j = request.get_json(silent=True) or {}
    ok = wordlists.delete_wordlist(j.get("name") or "")
    return jsonify({"ok": ok}), (200 if ok else 400)


@app.route("/api/llm/metrics")
def api_llm_metrics():
    from src.llm_metrics import LATEST
    if not os.path.exists(LATEST):
        return jsonify({"available": False}), 200
    try:
        with open(LATEST) as f:
            return jsonify({"available": True, "metrics": json.load(f)}), 200
    except Exception as e:
        return jsonify({"available": False, "error": str(e)}), 200


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

    # Scheduler de CVEs (#4): atualiza a base a cada N horas (padrao 12).
    if os.getenv("CVE_AUTO_UPDATE", "true").lower() in ("1", "true", "yes", "on"):
        hrs = float(os.getenv("CVE_UPDATE_HOURS", "12"))
        at_start = os.getenv("CVE_RUN_AT_START", "false").lower() in ("1", "true", "yes", "on")
        try:
            cve_scheduler.start_background(interval_hours=hrs, run_at_start=at_start)
        except Exception as e:
            print(f"[WEBUI] scheduler de CVE nao iniciado: {e}")

    app.run(host="0.0.0.0", port=port, threaded=True)
