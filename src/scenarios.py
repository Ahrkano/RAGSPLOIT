# -*- coding: utf-8 -*-
"""Registro UNICO dos CASOS DE USO (experimentos de validacao da pesquisa).

Fonte de verdade para a aba web "Casos de uso" e, depois, para o menu CLI.
Cada cenario descreve: o script a rodar, o tipo (attack = terminal PTT ao vivo;
ablation = lote que gera CSV), os campos do formulario de config rapida e como
montar o argv (validado — evita passar lixo aos pipelines).

So stdlib no topo (a UI importa isto para listar sem carregar nada pesado).
"""
import os
import re
import csv
import glob
import ipaddress

LOGS_DIR = "/app/data/logs"

# scripts permitidos (allowlist — nunca executa caminho arbitrario)
SCRIPTS = {
    "pipe_v4": "pipe_v4.py",
    "pipe_multi": "pipe_multi.py",
    "benchmark": "benchmark_llm2.py",
}

SCENARIOS = [
    {
        "id": "single", "name": "1 · Alvo único", "group": "Alvo único",
        "kind": "attack", "script": "pipe_v4",
        "description": "Recon de um IP e exploração autônoma de ponta a ponta "
                       "(TIER A/B/C, pós-exploração, privesc).",
        "fields": [
            {"name": "target", "label": "Alvo (IP)", "type": "text", "default": "",
             "placeholder": "vazio = usa config/target.json"},
            {"name": "port", "label": "Porta (vazio = todas)", "type": "number", "default": ""},
            {"name": "disable_rag", "label": "Desativar RAG (baseline)", "type": "checkbox", "default": False},
            {"name": "no_brute", "label": "Sem brute force", "type": "checkbox", "default": False},
            {"name": "explain", "label": "Modo explain (narrativa)", "type": "checkbox", "default": True},
        ],
    },
    {
        "id": "ab_rag", "name": "2 · Alvo único — A/B RAG", "group": "Alvo único",
        "kind": "attack", "script": "pipe_v4",
        "description": "Teste A/B numa porta: rode uma vez com RAG e outra sem, "
                       "para isolar o efeito do RAG (padrão: Samba porta 139).",
        "fields": [
            {"name": "target", "label": "Alvo (IP)", "type": "text", "default": "192.168.70.30"},
            {"name": "port", "label": "Porta", "type": "number", "default": "139"},
            {"name": "disable_rag", "label": "Sem RAG (marque p/ o braço Zero-Shot)", "type": "checkbox", "default": False},
            {"name": "explain", "label": "Modo explain", "type": "checkbox", "default": True},
        ],
    },
    {
        "id": "ablation", "name": "2b · Ablação (10 modelos, ZS × RAG)", "group": "Alvo único",
        "kind": "ablation", "script": "benchmark",
        "description": "Benchmark Samba CVE-2007-2447 nos 10 modelos, comparando "
                       "Zero-Shot vs RAG. Gera um CSV por braço (veja os resultados abaixo).",
        "fields": [
            {"name": "arm", "label": "Braço", "type": "select", "default": "rag",
             "options": [{"value": "rag", "label": "Com RAG"},
                         {"value": "zs", "label": "Zero-Shot (sem RAG)"}]},
        ],
    },
    {
        "id": "multi", "name": "3 · Multi-alvo (CIDR)", "group": "Multi-alvo",
        "kind": "attack", "script": "pipe_multi",
        "description": "Black-box parcial: varre o CIDR (ping sweep + banners), a "
                       "IA escolhe o alvo primário pela política do RAG e ataca.",
        "fields": [
            {"name": "network", "label": "Rede (CIDR)", "type": "text", "default": "192.168.70.0/24"},
            {"name": "test_mode", "label": "Modo teste rápido (5 IPs)", "type": "checkbox", "default": True},
            {"name": "disable_rag", "label": "Desativar RAG", "type": "checkbox", "default": False},
            {"name": "no_brute", "label": "Sem brute force", "type": "checkbox", "default": False},
            {"name": "explain", "label": "Modo explain", "type": "checkbox", "default": True},
        ],
    },
    {
        "id": "web", "name": "4 · Web (OWASP Juice Shop)", "group": "Web",
        "kind": "attack", "script": "pipe_v4",
        "description": "Alvo web: enumera e explora vulnerabilidades de lógica do "
                       "Juice Shop via TIER C (SQLi/JWT/IDOR).",
        "fields": [
            {"name": "target", "label": "Alvo (IP)", "type": "text", "default": "192.168.70.31"},
            {"name": "port", "label": "Porta", "type": "number", "default": "3000"},
            {"name": "disable_rag", "label": "Desativar RAG", "type": "checkbox", "default": False},
            {"name": "explain", "label": "Modo explain", "type": "checkbox", "default": True},
        ],
    },
]

_BY_ID = {s["id"]: s for s in SCENARIOS}


def get(scenario_id):
    return _BY_ID.get(scenario_id)


def grouped():
    """Lista [(grupo, [cenarios])] preservando a ordem de declaracao."""
    groups, order = {}, []
    for s in SCENARIOS:
        g = s["group"]
        if g not in groups:
            groups[g] = []; order.append(g)
        groups[g].append(s)
    return [(g, groups[g]) for g in order]


def _ip_ok(v):
    try:
        ipaddress.ip_address(v); return True
    except Exception:
        return False


def _cidr_ok(v):
    try:
        ipaddress.ip_network(v, strict=False); return True
    except Exception:
        return False


class ScenarioError(ValueError):
    pass


def build_command(scenario_id, params):
    """Valida os params e devolve {script_file, argv, kind, label}. Levanta
    ScenarioError com mensagem amigavel se algo estiver invalido. argv e lista
    (sem shell), mas validamos para nao passar valores sem sentido aos pipelines."""
    sc = _BY_ID.get(scenario_id)
    if not sc:
        raise ScenarioError("cenário desconhecido")
    p = params or {}
    script_file = SCRIPTS[sc["script"]]
    argv = []

    def _truthy(name):
        v = p.get(name)
        return v in (True, "true", "True", "on", "1", 1)

    if sc["script"] == "pipe_v4":
        target = (p.get("target") or "").strip()
        if target:
            if not _ip_ok(target):
                raise ScenarioError(f"IP inválido: {target}")
            argv += ["--target", target]
        port = (str(p.get("port") or "")).strip()
        if port:
            try:
                n = int(port)
                if not (1 <= n <= 65535):
                    raise ValueError
            except ValueError:
                raise ScenarioError(f"porta inválida: {port}")
            argv += ["--port", str(n)]
        if _truthy("disable_rag"): argv.append("--disable-rag")
        if _truthy("no_brute"):    argv.append("--no-brute")
        if _truthy("explain"):     argv.append("--explain")
        if _truthy("resume"):      argv.append("--resume")
        label = f"{sc['name']} → {target or '(target.json)'}" + (f":{port}" if port else "")

    elif sc["script"] == "pipe_multi":
        net = (p.get("network") or "").strip()
        if not net or not _cidr_ok(net):
            raise ScenarioError(f"CIDR inválido: {net or '(vazio)'}")
        argv += ["--network", net]
        if _truthy("test_mode"):   argv.append("--test")
        if _truthy("disable_rag"): argv.append("--disable-rag")
        if _truthy("no_brute"):    argv.append("--no-brute")
        if _truthy("explain"):     argv.append("--explain")
        label = f"{sc['name']} → {net}"

    elif sc["script"] == "benchmark":
        arm = (p.get("arm") or "rag").strip()
        if arm not in ("rag", "zs"):
            raise ScenarioError(f"braço inválido: {arm}")
        argv.append("--rag_enable" if arm == "rag" else "--rag_disable")
        label = f"{sc['name']} → {'Com RAG' if arm == 'rag' else 'Zero-Shot'}"
    else:
        raise ScenarioError("script não suportado")

    return {"script_file": script_file, "argv": argv, "kind": sc["kind"], "label": label}


# --- Resultados da ablacao (UC2b): CSVs gerados pelo benchmark_llm2 ---
def list_ablation_results(logs_dir=LOGS_DIR, limit=12):
    """Lista os CSVs de ablacao mais recentes, ja parseados (p/ a visao de resultados)."""
    out = []
    try:
        files = sorted(glob.glob(os.path.join(logs_dir, "benchmark_v2_samba_*.csv")),
                       key=os.path.getmtime, reverse=True)[:limit]
    except Exception:
        files = []
    for fp in files:
        name = os.path.basename(fp)
        arm = "Com RAG" if "COM_RAG" in name else ("Zero-Shot" if "SEM_RAG" in name else "?")
        rows, cols = [], []
        try:
            with open(fp, newline="") as f:
                r = csv.DictReader(f)
                cols = r.fieldnames or []
                for row in r:
                    rows.append(row)
        except Exception:
            continue
        try:
            mtime = int(os.path.getmtime(fp))
        except Exception:
            mtime = 0
        out.append({"file": name, "arm": arm, "columns": cols, "rows": rows, "mtime": mtime})
    return out
