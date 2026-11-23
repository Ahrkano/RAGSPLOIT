# -*- coding: utf-8 -*-
"""
Administracao da base de conhecimento (RAG) — logica reutilizavel por CLI,
TUI (orchestrator_db), Web UI e scheduler.

Cobre:
  #4 atualizacao dos CVEs (via DB_02 / API NVD) + re-ingestao idempotente;
  #5 reset da base do RAG a partir dos arquivos fornecidos (config/ingest)
     e da API de CVEs.

O cache de embeddings (data/vectorstore/emb_cache) e PRESERVADO nos resets,
entao reconstruir a base reaproveita vetores ja calculados (rapido).
"""
import os
import sys
import glob
import json
import time
import shutil
import datetime
import subprocess

# Silencia a telemetria do ChromaDB (ruido no stderr).
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")

BASE = "/app"
SRC = os.path.join(BASE, "src")
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from config import settings  # noqa: E402

DB02 = os.path.join(SRC, "DB_02_nvd_cves.py")
CVE_FILE = os.path.join(settings.DATA_PATH, "kb_recent_threats.txt")
CHROMA_DIR = os.path.join(settings.VECTORSTORE_PATH, "chromadb")
EMB_CACHE_DIR = os.path.join(settings.VECTORSTORE_PATH, "emb_cache")
STATE_FILE = os.path.join("/app/data/logs", "cve_last_update.json")
COLLECTION = "security_knowledge"


# ------------------------------------------------------------------ utilidades
def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _set_state(**kw):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        data = {}
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE) as f:
                data = json.load(f)
        data.update(kw)
        with open(STATE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def get_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _chroma_count():
    """Conta vetores sem carregar o modelo de embeddings (rapido)."""
    try:
        import chromadb
        client = chromadb.PersistentClient(path=CHROMA_DIR)
        return client.get_or_create_collection(COLLECTION).count()
    except Exception:
        return -1


def rag_stats():
    emb = 0
    if os.path.isdir(EMB_CACHE_DIR):
        try:
            emb = len(os.listdir(EMB_CACHE_DIR))
        except Exception:
            emb = -1
    st = get_state()
    return {
        "doc_count": _chroma_count(),
        "emb_cache_entries": emb,
        "cve_file_exists": os.path.exists(CVE_FILE),
        "cve_file_mtime": (int(os.path.getmtime(CVE_FILE))
                           if os.path.exists(CVE_FILE) else None),
        "last_cve_update": st.get("last_cve_update"),
        "last_reset": st.get("last_reset"),
        "chroma_dir": CHROMA_DIR,
    }


# ------------------------------------------------------------------ ingestao
def _ingest_files(rag, files, replace=True):
    """Ingere arquivos .txt. Com replace=True, remove antes os docs da mesma
    'source' (re-ingestao idempotente — evita duplicar ao atualizar)."""
    total = 0
    for path in files:
        src = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            print(f"[RAG_ADMIN] erro lendo {src}: {e}")
            continue
        if not content.strip():
            continue
        if replace:
            try:
                rag.vectordb._collection.delete(where={"source": src})
            except Exception:
                pass
        rag.ingest_data([content], [{"source": src}])
        total += 1
    return total


def update_cves(ingest=True, api_key=None):
    """#4 — roda o coletor de CVEs (DB_02, API NVD) e re-ingere o resultado."""
    env = os.environ.copy()
    if api_key:
        env["NVD_API_KEY"] = api_key
    print("[RAG_ADMIN] Atualizando CVEs via NVD...")
    r = subprocess.run([sys.executable, DB02], cwd=BASE, env=env,
                       capture_output=True, text=True, timeout=120)
    ok = (r.returncode == 0 and os.path.exists(CVE_FILE))
    out = (r.stdout or "")[-1500:]
    err = (r.stderr or "")[-800:]
    ingested = 0
    if ok and ingest:
        from src.rag_engine import RagEngine
        rag = RagEngine()
        ingested = _ingest_files(rag, [CVE_FILE], replace=True)
    if ok:
        _set_state(last_cve_update=_now())
    return {"ok": ok, "ingested_files": ingested, "stdout": out, "stderr": err,
            "when": _now(), "doc_count": _chroma_count()}


def reset_rag(fetch_cves=True, api_key=None):
    """#5 — reconstroi a base: (opcional) atualiza CVEs, apaga o ChromaDB e
    re-ingere TODOS os arquivos de config/ingest. Preserva o emb_cache."""
    report = {"when": _now(), "fetch_cves": fetch_cves}

    if fetch_cves:
        cve = update_cves(ingest=False, api_key=api_key)  # so atualiza o arquivo
        report["cve_refresh"] = {"ok": cve["ok"], "stderr": cve["stderr"]}

    # Wipe apenas do banco vetorial (mantem emb_cache -> reconstrucao rapida).
    print("[RAG_ADMIN] Apagando ChromaDB (emb_cache preservado)...")
    if os.path.isdir(CHROMA_DIR):
        shutil.rmtree(CHROMA_DIR, ignore_errors=True)
    os.makedirs(CHROMA_DIR, exist_ok=True)

    from src.rag_engine import RagEngine
    rag = RagEngine()
    files = sorted(glob.glob(os.path.join(settings.DATA_PATH, "*.txt")))
    print(f"[RAG_ADMIN] Re-ingerindo {len(files)} arquivos de {settings.DATA_PATH}...")
    n = _ingest_files(rag, files, replace=False)  # banco vazio -> sem dup
    _set_state(last_reset=_now(), last_cve_update=(_now() if fetch_cves else
                                                   get_state().get("last_cve_update")))
    report.update({"ok": True, "files_ingested": n, "doc_count": rag.count(),
                   "sources": [os.path.basename(f) for f in files]})
    return report


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Admin da base RAG (CVEs/reset)")
    ap.add_argument("cmd", choices=["stats", "update-cves", "reset"])
    ap.add_argument("--no-cves", action="store_true",
                    help="no reset, nao rebuscar CVEs")
    a = ap.parse_args()
    if a.cmd == "stats":
        result = rag_stats()
    elif a.cmd == "update-cves":
        result = update_cves()
    elif a.cmd == "reset":
        result = reset_rag(fetch_cves=not a.no_cves)
    # Linha-marcador para consumo por outros processos (ex.: Web UI).
    print("RAGADMIN_JSON:" + json.dumps(result))
