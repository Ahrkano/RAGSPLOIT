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
import re
import sys
import json
import glob
import statistics
import html as _html
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
                   abort, session, redirect, url_for)
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
from src import health_checks                     # noqa: E402

LOGS_DIR = "/app/data/logs"
RAG_ADMIN = os.path.join(SRC, "rag_admin.py")
HEALTH_CHECKS = os.path.join(SRC, "health_checks.py")
VSTORE = os.getenv("CHROMA_PERSIST_DIR", "/app/data")
CVE_FILE = "/app/config/ingest/kb_recent_threats.txt"
CVE_STATE = os.path.join(LOGS_DIR, "cve_last_update.json")

# Pipelines de alvo unico que aceitam --target (allowlist — nunca executamos
# caminho arbitrario vindo do cliente).
ALLOWED_PIPELINES = {
    "pipe_v4.py": "Ataque autonomo (single target)",
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
# Recarrega templates do disco a cada request (src/ e montado como volume):
# edicoes de UI aparecem sem rebuild/restart do container. Custo irrelevante
# para esta ferramenta interna.
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True
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


@app.after_request
def _no_store_html(resp):
    # Paginas dinamicas (ex.: Reports) nao podem ser servidas do cache/bfcache
    # do navegador, senao uma nova execucao nao aparece ate um hard-refresh.
    # Estaticos (/static/*: js/css) continuam cacheaveis.
    try:
        if (resp.mimetype or "").startswith("text/html"):
            resp.headers["Cache-Control"] = "no-store, must-revalidate"
    except Exception:
        pass
    return resp


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
    return render_template("reports.html", st=current_state(), logs=logs)


@app.route("/knowledge")
def knowledge_page():
    return render_template("knowledge.html", st=current_state())


@app.route("/checklist")
def checklist_page():
    # Agrupa os checks por categoria preservando a ordem do registro.
    groups, order = {}, []
    for c in health_checks.CHECKS:
        g = c.get("group", "Geral")
        if g not in groups:
            groups[g] = []; order.append(g)
        groups[g].append(c)
    grouped = [(g, groups[g]) for g in order]
    return render_template("checklist.html", st=current_state(), grouped=grouped)


_HC_IDS = {c["id"] for c in health_checks.CHECKS}


def _run_hc(cid, timeout=150):
    """Roda UM health check em subprocesso (isola ChromaDB/torch/MSF do Flask) e
    extrai o JSON marcado com @@HC@@, ignorando banners de stdout dos componentes."""
    try:
        r = subprocess.run([sys.executable, HEALTH_CHECKS, cid, "--json"],
                           cwd=BASE, env=os.environ.copy(),
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"id": cid, "ok": False,
                "output": f"tempo esgotado (> {timeout}s): o componente nao respondeu.",
                "duration_ms": timeout * 1000}
    except Exception as e:
        return {"id": cid, "ok": False, "output": f"falha ao executar o check: {e}",
                "duration_ms": 0}
    for line in reversed((r.stdout or "").splitlines()):
        if health_checks.HC_MARK in line:
            try:
                return json.loads(line.split(health_checks.HC_MARK, 1)[1])
            except Exception:
                break
    return {"id": cid, "ok": False,
            "output": "sem resultado do check.\nstderr: " + (r.stderr or "")[-600:],
            "duration_ms": 0}


@app.route("/api/check/<cid>", methods=["POST"])
def api_check(cid):
    if cid not in _HC_IDS:
        return jsonify({"error": "check desconhecido"}), 404
    # Checks que abrem o ChromaDB nao podem rodar concorrentes a um job de
    # RAG/ingestao (lock do banco): devolve 'ocupado' em vez de colidir.
    if cid in health_checks.RAG_CHECKS:
        with _JOB_LOCK:
            busy = _JOB["running"]
        if busy:
            return jsonify({"id": cid, "ok": None, "skipped": True,
                            "output": "Base de conhecimento ocupada (ingestao/reset em "
                                      "andamento). Tente novamente ao concluir."}), 200
    return jsonify(_run_hc(cid)), 200


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
# Relatorio de execucao: <IP_com_underscores>_<AAAA-MM-DD>_<HH-MM-SS>.txt
# (ex.: 192_168_70_30_2026-11-24_13-08-28.txt). Filtra loot/arquivos avulsos.
_REPORT_RE = re.compile(
    r"^(\d{1,3})_(\d{1,3})_(\d{1,3})_(\d{1,3})_"
    r"(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})\.txt$")


def _report_label(name):
    """Rotulo amigavel: '192.168.70.30 | 24/11/2026 - 13:08:28'."""
    m = _REPORT_RE.match(name)
    if not m:
        return name
    o1, o2, o3, o4, Y, Mo, D, H, Mi, S = m.groups()
    return f"{o1}.{o2}.{o3}.{o4} | {D}/{Mo}/{Y} - {H}:{Mi}:{S}"


def _list_logs():
    if not os.path.isdir(LOGS_DIR):
        return []
    files = sorted(glob.glob(os.path.join(LOGS_DIR, "*.txt")),
                   key=os.path.getmtime, reverse=True)
    out = []
    for f in files:
        base = os.path.basename(f)
        if not _REPORT_RE.match(base):
            continue
        out.append({
            "name": base,
            "label": _report_label(base),
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


def _report_to_html(name, text):
    """Converte um relatorio .txt (DATA/STATUS/PORTAS/HISTORICO/EVIDENCIAS)
    num HTML standalone estilizado, especifico daquela execucao."""
    e = _html.escape
    data = status = portas = ""
    hist, evid = [], []
    section = None
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("DATA:"):
            data = s[5:].strip()
        elif s.startswith("STATUS:"):
            status = s[7:].strip()
        elif s.startswith("PORTAS:"):
            portas = s[7:].strip()
        elif s == "[HISTORICO]":
            section = "h"
        elif s == "[EVIDENCIAS]":
            section = "e"
        elif section == "h" and s.startswith("-"):
            hist.append(s.lstrip("- ").strip())
        elif section == "e" and s:
            evid.append(ln)
    pwned = status.upper() == "PWNED"
    badge_cls = "pwned" if pwned else "failed"
    # Portas: "['21', '22']" -> chips "21 22"
    ports = re.findall(r"\d+", portas)
    chips = "".join(f'<span class="chip">{p}</span>' for p in ports) or \
        '<span class="muted">nenhuma</span>'
    hist_html = ""
    for h in hist:
        ok = "SUCESSO" in h.upper()
        hist_html += (f'<li class="{"ok" if ok else "no"}">'
                      f'{"[+] " if ok else "[-] "}{e(h)}</li>')
    if not hist_html:
        hist_html = '<li class="muted">sem tentativas registradas</li>'
    evid_txt = e("\n".join(evid).strip() or "sem evidencias")
    label = e(_report_label(name))
    return f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8">
<title>Relatorio {label} - RAGSPLOIT</title>
<style>
  body{{font-family:'Consolas','Monaco',monospace;background:#0d0d0d;color:#ccc;margin:0;padding:28px}}
  h1{{color:#50fa7b;border-bottom:2px solid #50fa7b;padding-bottom:10px;font-size:22px}}
  h2{{color:#bd93f9;margin-top:28px;font-size:16px}}
  .meta{{color:#888;font-size:13px;margin:6px 0 18px}}
  .badge{{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;color:#05140a}}
  .badge.pwned{{background:#50fa7b}} .badge.failed{{background:#ff5555;color:#190505}}
  .card{{background:#1a1a1a;border:1px solid #333;border-left:5px solid #6272a4;
         padding:14px 16px;margin:12px 0;border-radius:6px}}
  .card.success{{border-left-color:#50fa7b}} .card.info{{border-left-color:#8be9fd}}
  .chip{{display:inline-block;background:#111;border:1px solid #333;border-radius:999px;
         padding:2px 10px;margin:3px;font-size:12px;color:#8be9fd}}
  ul{{list-style:none;padding:0;margin:0}} li{{padding:4px 0}}
  li.ok{{color:#50fa7b}} li.no{{color:#ff5555}} .muted{{color:#666}}
  pre{{background:#000;border:1px solid #444;color:#f1fa8c;padding:12px;overflow-x:auto;white-space:pre-wrap}}
  footer{{margin-top:40px;text-align:center;color:#444;font-size:12px}}
</style></head><body>
  <h1>RAGSPLOIT // RELATORIO DE EXECUCAO</h1>
  <div class="meta">{label} &nbsp;|&nbsp; {e(data) or 'sem data'} &nbsp;|&nbsp;
      <span class="badge {badge_cls}">{e(status or 'UNKNOWN')}</span></div>
  <h2>Portas identificadas</h2>
  <div class="card info">{chips}</div>
  <h2>Timeline de tentativas</h2>
  <div class="card success"><ul>{hist_html}</ul></div>
  <h2>Evidencias de comprometimento</h2>
  <div class="card"><pre>{evid_txt}</pre></div>
  <footer>RAGSPLOIT - Autonomous Red Team Operations Platform<br>
    Powered by LLM &amp; Metasploit Framework</footer>
</body></html>"""


@app.route("/api/report/html")
def api_report_html():
    name = request.args.get("name", "")
    path = _safe_log_path(name)
    if not path:
        abort(404)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    return Response(_report_to_html(os.path.basename(path), text),
                    mimetype="text/html; charset=utf-8")


# --- Estatisticas de pesquisa (por provedor de LLM) ---
# So entram runs com o schema "ragsploit.run/1" (runstats_*.json gravado pelo
# pipeline). Runs/logs antigos sem esse marcador nao sao classificaveis.
_PROVIDERS = ["OpenAI", "Google", "Anthropic", "Local"]


def _norm_provider(p):
    s = (p or "").strip().lower()
    if not s:
        return None
    if "openai" in s or s.startswith("gpt"):
        return "OpenAI"
    if "anthropic" in s or "claude" in s:
        return "Anthropic"
    if "gemini" in s or "google" in s:
        return "Google"
    if "local" in s:
        return "Local"
    return None


def _pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def _new_bucket():
    return {"runs": 0, "pwned": 0, "calls": 0, "ok": 0, "json_valid": 0,
            "latencies": [], "tokens": 0, "rag_on": 0, "rag_off": 0,
            "models": set()}


def _add_to_bucket(b, rec, m):
    b["runs"] += 1
    if rec.get("pwned"):
        b["pwned"] += 1
    b["calls"] += int(m.get("calls") or 0)
    b["ok"] += int(m.get("ok") or 0)
    b["json_valid"] += int(m.get("json_valid") or 0)
    b["tokens"] += int(m.get("total_tokens") or 0)
    b["latencies"] += [float(x) for x in (rec.get("latencies") or [])]
    if rec.get("model"):
        b["models"].add(rec["model"])
    re_flag = rec.get("rag_enabled")
    if re_flag is True:
        b["rag_on"] += 1
    elif re_flag is False:
        b["rag_off"] += 1


def _summarize_bucket(b):
    lats = b["latencies"]
    n = len(lats)
    calls = b["calls"]
    return {
        "runs": b["runs"],
        "pwned": b["pwned"],
        "attack_success_rate": round(b["pwned"] / b["runs"], 3) if b["runs"] else None,
        "calls": calls,
        "accuracy": round(b["json_valid"] / calls, 3) if calls else None,
        "llm_success_rate": round(b["ok"] / calls, 3) if calls else None,
        "llm_error_rate": round(1 - b["ok"] / calls, 3) if calls else None,
        "latency_avg": round(sum(lats) / n, 3) if n else None,
        "latency_std": (round(statistics.pstdev(lats), 3) if n > 1
                        else (0.0 if n == 1 else None)),
        "latency_p95": round(_pct(lats, 95), 3) if n else None,
        "latency_min": round(min(lats), 3) if n else None,
        "latency_max": round(max(lats), 3) if n else None,
        "tokens": b["tokens"] or None,
        "rag_on": b["rag_on"],
        "rag_off": b["rag_off"],
        "models": sorted(b["models"]),
    }


def _short_model(name):
    """Rotulo curto de modelo: remove prefixo de provedor (gemini/, openai/,
    anthropic/) p/ exibicao. 'anthropic/claude-opus-4-8' -> 'claude-opus-4-8'."""
    s = (name or "").strip()
    return s.split("/", 1)[1] if "/" in s else s


def _collect_stats():
    buckets = {p: _new_bucket() for p in _PROVIDERS}
    model_buckets = {}   # chave: nome cru do modelo -> bucket (+ provider)
    total = classified = 0
    for f in glob.glob(os.path.join(LOGS_DIR, "runstats_*.json")):
        try:
            with open(f, encoding="utf-8") as fh:
                rec = json.load(fh)
        except Exception:
            continue
        if rec.get("schema") != "ragsploit.run/1":
            continue
        total += 1
        prov = _norm_provider(rec.get("provider"))
        if prov is None:
            continue
        classified += 1
        m = rec.get("metrics") or {}
        _add_to_bucket(buckets[prov], rec, m)
        model = (rec.get("model") or "desconhecido").strip() or "desconhecido"
        mb = model_buckets.get(model)
        if mb is None:
            mb = model_buckets[model] = _new_bucket()
            mb["_provider"] = prov
        _add_to_bucket(mb, rec, m)

    out = {p: _summarize_bucket(buckets[p]) for p in _PROVIDERS}

    models = []
    for name, mb in model_buckets.items():
        row = _summarize_bucket(mb)
        row["model"] = name
        row["label"] = _short_model(name)
        row["provider"] = mb.get("_provider")
        models.append(row)
    # mais usados primeiro, depois por nome
    models.sort(key=lambda r: (-r["runs"], r["label"]))

    return {"providers": out, "order": _PROVIDERS, "models": models,
            "total_runs": total, "classified_runs": classified}


@app.route("/api/stats")
def api_stats():
    return jsonify(_collect_stats())


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
    if cfg.get("disable_rag"):
        extra.append("--disable-rag")
    if cfg.get("no_brute"):
        extra.append("--no-brute")
    # Porta opcional: vazio => recon completo (todas as portas); numero valido
    # => restringe o ataque aquela porta. Validado como inteiro 1-65535 (argv e
    # lista, sem shell, mas validamos para nao passar lixo ao pipeline).
    port = cfg.get("port")
    if port not in (None, "", False):
        try:
            pnum = int(port)
            if 1 <= pnum <= 65535:
                extra += ["--port", str(pnum)]
        except (TypeError, ValueError):
            pass

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

    # IMPORTANTE: todas as operacoes do WebSocket (send E receive) ficam neste
    # UNICO thread. simple_websocket nao suporta acesso concorrente ao mesmo
    # socket por dois threads — a versao anterior lia o PTY num thread separado
    # que chamava ws.send() enquanto este thread chamava ws.receive(), o que
    # corrompia a maquina de estados e derrubava a conexao (ConnectionClosed
    # 1000) logo apos o banner. Aqui um unico loop drena o PTY (select nao
    # bloqueante) e le a entrada do cliente (receive com timeout curto).
    try:
        while True:
            # 1) Saida do pipeline (PTY) -> cliente, priorizando esvaziar o PTY.
            try:
                r, _, _ = select.select([master], [], [], 0.05)
            except (OSError, ValueError):
                break
            if master in r:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    data = b""
                if not data:
                    break  # EOF do PTY -> processo encerrou
                ws.send(data.decode(errors="ignore"))
                continue
            # 2) Entrada do cliente (teclado / resize), sem bloquear o loop.
            try:
                msg = ws.receive(timeout=0.05)
            except Exception:
                break  # cliente desconectou
            if msg is None:
                if proc.poll() is not None:   # processo terminou e PTY drenado
                    break
                continue
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
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        try:
            os.close(master)
        except Exception:
            pass
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
