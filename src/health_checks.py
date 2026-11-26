#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Registro UNICO de verificacoes de saude da ferramenta (health checks).

Cada check e uma funcao que devolve (ok: bool, output: str). O topo do modulo
so usa stdlib (importar o registro de metadados e barato); os imports pesados
(torch/chromadb/pymetasploit/requests) ficam LAZY dentro de cada funcao, para
que a aba web possa listar os checks sem carregar nada.

Uso:
  - A aba "Checklist" do webui roda cada check isolado por subprocess:
        python src/health_checks.py <id> --json
    (saida: um objeto JSON por check; 'all' roda todos e imprime uma lista).
  - CLI humana (terminal):  python src/health_checks.py all
"""
import os
import sys
import json
import time
import socket

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MSF_HOST = os.getenv("MSF_RPC_HOST", "192.168.70.20")
MSF_PASS = os.getenv("MSF_RPC_PASSWORD", "msfpass")


# =========================================================================
# CHECKS (cada um retorna (ok, output))
# =========================================================================
def check_filesystem():
    """I/O: escrita no volume de dados (logs/relatorios/evidencias)."""
    path = "/app/data/logs"
    test = os.path.join(path, ".health_write_test")
    try:
        os.makedirs(path, exist_ok=True)
        with open(test, "w") as f:
            f.write("ok")
        os.remove(test)
        return True, f"Escrita OK em {path}."
    except Exception as e:
        return False, f"Sem permissao de escrita em {path}: {e}"


def check_metasploit():
    """Conexao com o Metasploit RPC (o MOTOR dos TIER A/B)."""
    try:
        from src.metasploit_client import MetasploitClient
        client = MetasploitClient(password=MSF_PASS, server=MSF_HOST)
        ver = client.client.call("core.version") or {}
        return True, (f"Conectado a {MSF_HOST}:55553.\n"
                      f"core.version: {ver.get('version')}\n"
                      f"ruby: {ver.get('ruby')}  api: {ver.get('api')}")
    except Exception as e:
        return False, f"Falha ao conectar no MSF RPC ({MSF_HOST}): {e}"


def check_target_network():
    """Alcance de rede ate o ALVO configurado (config/target.json).
    Nao decide ataque: so verifica se a rede chega ao host."""
    try:
        from src.pipeline_common import resolve_target
        target = resolve_target(None)
    except Exception as e:
        return False, f"Nao foi possivel resolver o alvo: {e}"
    ports = [21, 22, 80, 139, 443, 445, 3000, 3306, 8080]
    reachable, open_ports, refused = False, [], 0
    lines = [f"Alvo: {target}", "Sondando TCP em %s ..." % ", ".join(map(str, ports))]
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        rc = s.connect_ex((target, p))
        s.close()
        if rc == 0:
            open_ports.append(p); reachable = True
        elif rc in (111, 61):          # connection refused => host responde
            refused += 1; reachable = True
    if open_ports:
        lines.append("Portas ABERTAS: " + ", ".join(map(str, open_ports)))
    if refused:
        lines.append(f"{refused} porta(s) recusaram conexao (host vivo, porta fechada).")
    if reachable:
        lines.append("=> Rede alcanca o alvo.")
        return True, "\n".join(lines)
    lines.append("=> Nenhuma resposta: alvo inalcancavel (rota/firewall) ou desligado.")
    return False, "\n".join(lines)


def check_llm():
    """Conectividade com o modelo de linguagem (provedor ativo)."""
    try:
        from src.llm_client import LLMClient
        llm = LLMClient()
        t0 = time.time()
        resp = (llm.ask("Responda apenas com a palavra FUNCIONANDO.") or "").strip()
        dt = time.time() - t0
        model = getattr(llm, "model_name", "?")
        if resp:
            tag = "resposta esperada" if ("FUNCIONANDO" in resp.upper()
                                          or "WORKING" in resp.upper()) else "respondeu (texto diferente)"
            return True, f"Modelo: {model}\nLatencia: {dt:.1f}s ({tag})\nResposta: {resp[:200]}"
        return False, f"Modelo {model} nao retornou resposta."
    except Exception as e:
        return False, f"Falha na comunicacao com o LLM: {e}"


def check_rag_db():
    """Banco vetorial (RAG) existe e esta PREENCHIDO."""
    try:
        from src.rag_engine import RagEngine
        rag = RagEngine()
        n = rag.count()
        snap = {}
        try:
            snap = rag.snapshot()
        except Exception:
            pass
        if n and n > 0:
            return True, (f"ChromaDB OK em {rag.persist_directory}\n"
                          f"Vetores: {n}\n"
                          f"Embeddings: {snap.get('embedding_model','?')}\n"
                          f"Fontes de ingestao: {snap.get('sources_files','?')} "
                          f"(sha256 {snap.get('sources_sha256')})")
        return False, f"Banco vazio (0 vetores) em {rag.persist_directory}. Rode a ingestao do RAG."
    except Exception as e:
        return False, f"Falha ao abrir o RAG: {e}"


def check_rag_retrieval():
    """Recuperacao de informacao no RAG (query -> documentos relevantes)."""
    try:
        from src.rag_engine import RagEngine
        rag = RagEngine()
        query = "vsftpd 2.3.4 backdoor exploit metasploit"
        docs = rag.query(query, k=3)
        if not docs:
            return False, f"Query '{query}' retornou 0 documentos (banco vazio/corrompido?)."
        lines = [f"Query: {query}", f"Recuperados: {len(docs)} documento(s)", ""]
        for i, d in enumerate(docs, 1):
            src = (d.metadata or {}).get("source", "?")
            prev = d.page_content.replace("\n", " ")[:160]
            lines.append(f"#{i} [{src}] {prev}...")
        return True, "\n".join(lines)
    except Exception as e:
        return False, f"Falha na recuperacao do RAG: {e}"


def check_rag_canary():
    """Ponta-a-ponta (RAG -> LLM): injeta um fato-isca, recupera e verifica se
    o LLM RESPONDE COM BASE no RAG (nao alucina). Auto-limpa a isca depois."""
    SRCTAG = "canary_healthcheck"
    try:
        from src.rag_engine import RagEngine
        from src.llm_client import LLMClient
        rag = RagEngine()
        llm = LLMClient()
    except Exception as e:
        return False, f"Falha ao iniciar RAG/LLM: {e}"
    canary = ("=== CANARY HEALTHCHECK ===\n"
              "O servico ficticio 'Protocolo Fantasma v9.9' na porta 65000 exige a "
              "estrategia exploit_cve com o modulo 'exploit/linux/misc/fantasma_pwn' "
              "e a opcao MODO_FURTIVO=ativado.\n==========================")
    try:
        rag.ingest_data([canary], [{"source": SRCTAG}])
        docs = rag.query("qual modulo usar para o Protocolo Fantasma v9.9?", k=2)
        got = next((d.page_content for d in docs if "fantasma_pwn" in d.page_content), "")
        if not got:
            return False, "RAG nao recuperou a isca recem-inserida (busca/embeddings com problema)."
        prompt = (f"Use ESTRITAMENTE a base abaixo.\nRAG:\n{got}\n\n"
                  "Qual modulo Metasploit e qual opcao/valor para o Protocolo Fantasma v9.9?")
        resp = (llm.ask(prompt) or "")
        ok = ("fantasma_pwn" in resp) and ("MODO_FURTIVO" in resp)
        msg = ("RAG recuperou a isca e o LLM respondeu com base nela (grounding OK)."
               if ok else
               "RAG recuperou a isca, mas o LLM NAO usou o contexto (possivel alucinacao).")
        return ok, msg + "\n\nResposta do LLM:\n" + resp[:400]
    except Exception as e:
        return False, f"Falha no teste canario: {e}"
    finally:
        # limpa a isca para nao poluir o conhecimento
        try:
            rag.vectordb._collection.delete(where={"source": SRCTAG})
        except Exception:
            pass


def check_cve_nvd():
    """Conectividade com a fonte de CVEs NVD (NIST)."""
    try:
        import requests
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        r = requests.get(url, params={"cveId": "CVE-2011-2523"},
                         headers={"User-Agent": "RAGSPLOIT-healthcheck/1.0"}, timeout=20)
        if r.status_code != 200:
            return False, f"NVD respondeu HTTP {r.status_code}: {r.text[:200]}"
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        cid = vulns[0]["cve"]["id"] if vulns else "(vazio)"
        return True, f"NVD OK (HTTP 200). Consulta de sanidade retornou: {cid}"
    except Exception as e:
        return False, f"Falha ao acessar a NVD: {e}"


def check_cve_sources():
    """Estado das fontes de CVE configuradas (habilitadas / chave / ultimo update)."""
    try:
        from src import cve_sources
        st = cve_sources.status()
        enabled = [s for s in st if s.get("enabled")]
        lines = [f"Fontes configuradas: {len(st)} | habilitadas: {len(enabled)}"]
        for s in st:
            mark = "on " if s.get("enabled") else "off"
            if s.get("api_required"):
                keyn = " (chave obrigatoria: %s)" % ("ok" if s.get("has_key") else "FALTA")
            elif s.get("api_env"):
                keyn = " (chave opcional: %s)" % ("ok" if s.get("has_key") else "ausente")
            else:
                keyn = ""
            last = s.get("last_run")
            last = f" | ultimo: {last} ({s.get('last_count')})" if last else ""
            lines.append(f"  [{mark}] {s.get('name') or s.get('id')}{keyn}{last}")
        # OK = ha fonte habilitada e nenhuma habilitada com chave OBRIGATORIA faltando
        missing = [s for s in enabled if s.get("api_required") and not s.get("has_key")]
        if not enabled:
            return False, "\n".join(lines + ["=> Nenhuma fonte habilitada."])
        if missing:
            return False, "\n".join(lines + ["=> Fonte(s) habilitada(s) sem a chave obrigatoria."])
        return True, "\n".join(lines)
    except Exception as e:
        return False, f"Falha ao ler o estado das fontes: {e}"


# ordem = ordem de exibicao; group apenas organiza visualmente
CHECKS = [
    {"id": "filesystem",     "name": "Sistema de arquivos (I/O)",   "group": "Infraestrutura",
     "desc": "Escrita no volume de dados (logs/evidencias)."},
    {"id": "metasploit",     "name": "Metasploit RPC",              "group": "Infraestrutura",
     "desc": "Conexao com o msfrpcd (motor TIER A/B)."},
    {"id": "target_network", "name": "Rede do alvo",                "group": "Infraestrutura",
     "desc": "Alcance TCP ate o alvo configurado."},
    {"id": "llm",            "name": "Conexao com o LLM",           "group": "IA & Conhecimento",
     "desc": "Ping ao modelo do provedor ativo."},
    {"id": "rag_db",         "name": "RAG preenchido",              "group": "IA & Conhecimento",
     "desc": "ChromaDB existe e tem vetores."},
    {"id": "rag_retrieval",  "name": "Recuperacao no RAG",          "group": "IA & Conhecimento",
     "desc": "Query retorna documentos relevantes."},
    {"id": "rag_canary",     "name": "Grounding RAG->LLM (canario)", "group": "IA & Conhecimento",
     "desc": "LLM responde com base no RAG (sem alucinar)."},
    {"id": "cve_nvd",        "name": "Fonte de CVEs: NVD",          "group": "Fontes de dados",
     "desc": "Conectividade com a API da NVD/NIST."},
    {"id": "cve_sources",    "name": "Fontes de CVE configuradas",  "group": "Fontes de dados",
     "desc": "Fontes habilitadas e chaves presentes."},
]

_FUNCS = {
    "filesystem": check_filesystem,
    "metasploit": check_metasploit,
    "target_network": check_target_network,
    "llm": check_llm,
    "rag_db": check_rag_db,
    "rag_retrieval": check_rag_retrieval,
    "rag_canary": check_rag_canary,
    "cve_nvd": check_cve_nvd,
    "cve_sources": check_cve_sources,
}

# checks que abrem o ChromaDB (nao rodar concorrente a um job de RAG/ingestao)
RAG_CHECKS = {"rag_db", "rag_retrieval", "rag_canary"}


def run_check(cid):
    fn = _FUNCS.get(cid)
    if not fn:
        return {"id": cid, "ok": False, "output": "check desconhecido", "duration_ms": 0}
    t0 = time.time()
    try:
        ok, out = fn()
    except Exception as e:
        ok, out = False, f"excecao nao tratada: {e}"
    return {"id": cid, "ok": bool(ok), "output": str(out),
            "duration_ms": int((time.time() - t0) * 1000)}


def run_all():
    return [run_check(c["id"]) for c in CHECKS]


# Sentinela: o resultado JSON vai nesta linha, para o chamador (webui) extrair
# ignorando qualquer ruido de stdout dos componentes (MSF/LLM imprimem banners).
HC_MARK = "@@HC@@"

if __name__ == "__main__":
    args = sys.argv[1:]
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    which = args[0] if args else "all"
    if which == "all":
        results = run_all()
        if as_json:
            print(HC_MARK + json.dumps(results), flush=True)
        else:
            for r in results:
                tag = "OK  " if r["ok"] else "FAIL"
                print(f"[{tag}] {r['id']} ({r['duration_ms']}ms)\n       "
                      + r["output"].replace("\n", "\n       "))
    else:
        r = run_check(which)
        if as_json:
            print(HC_MARK + json.dumps(r), flush=True)
        else:
            print(f"[{'OK' if r['ok'] else 'FAIL'}] {r['id']}\n{r['output']}")
