# -*- coding: utf-8 -*-
"""
Coletores multi-fonte de CVE -> 'Threat Intel Cards' (mesmo formato dos .txt
ja existentes), consumidos pelo RAG.

Fontes suportadas:
  - nvd    : NVD / NIST (schema 2.0). Chave opcional (NVD_API_KEY) eleva rate.
  - circl  : CIRCL CVE Search / Vulnerability-Lookup (/api/last, formato OSV/GCVE).
             Sem chave. Feed de vulnerabilidades recentes (CVE/GHSA/PYSEC...).
  - mitre  : CVE.org / MITRE CVE Services (cveawg, schema CVE 5.x). Sem chave
             para leitura publica (chave opcional CVE_ORG_API_KEY). Nao tem feed
             'recentes' publico, entao ENRIQUECE os IDs de CVE recentes achados
             nas outras fontes, trazendo o registro autoritativo.

A configuracao das fontes (habilitada, chave, limite) vive em
config/cve_sources.json e e exposta/editavel pela pagina de Config da Web UI.
"""
import os
import sys
import json
import datetime

import requests

BASE = "/app"
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from config import settings  # noqa: E402

SOURCES_CONFIG = os.path.join(BASE, "config", "cve_sources.json")
OUTPUT_FILE = os.path.join(settings.DATA_PATH, "kb_recent_threats.txt")
STATE_FILE = os.path.join("/app/data/logs", "cve_sources_state.json")
UA = {"User-Agent": "Pentest-Lab-RAG/1.0 (Educational)"}
WINDOW_DAYS = 90

# Padrao das fontes (semente do config editavel).
DEFAULT_SOURCES = {
    "nvd": {
        "name": "NVD (NIST)", "enabled": True, "limit": 40,
        "api": {"required": False, "env": "NVD_API_KEY"},
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "docs": "https://nvd.nist.gov/developers/request-an-api-key",
    },
    "circl": {
        "name": "CIRCL CVE Search", "enabled": True, "limit": 30,
        "api": {"required": False, "env": None},
        "url": "https://cve.circl.lu/api/last",
        "docs": "https://www.circl.lu/services/cve-search/",
    },
    "mitre": {
        "name": "CVE.org (MITRE CVE Services)", "enabled": True, "limit": 15,
        "api": {"required": False, "env": "CVE_ORG_API_KEY"},
        "url": "https://cveawg.mitre.org/api/cve",
        "docs": "https://www.cve.org/AllResources/CveServices",
    },
}

AV_MAP = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}


# ----------------------------------------------------------------- config/estado
def load_sources():
    cfg = {}
    if os.path.exists(SOURCES_CONFIG):
        try:
            with open(SOURCES_CONFIG) as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
    # Merge com defaults (garante campos novos sem perder ajustes do usuario).
    merged = {}
    for sid, dflt in DEFAULT_SOURCES.items():
        cur = cfg.get(sid, {})
        m = json.loads(json.dumps(dflt))
        for k in ("enabled", "limit"):
            if k in cur:
                m[k] = cur[k]
        merged[sid] = m
    # Preserva fontes extras que o usuario tenha adicionado manualmente.
    for sid, cur in cfg.items():
        if sid not in merged:
            merged[sid] = cur
    return merged


def save_sources(cfg):
    os.makedirs(os.path.dirname(SOURCES_CONFIG), exist_ok=True)
    with open(SOURCES_CONFIG, "w") as f:
        json.dump(cfg, f, indent=2)


def _load_dotenv():
    try:
        from src import model_selector as ms
        ms.load_dot_env()
    except Exception:
        pass


def status():
    """Estado das fontes para a UI: habilitada, se usa API e se tem chave."""
    _load_dotenv()
    cfg = load_sources()
    st = _get_state()
    out = []
    for sid, s in cfg.items():
        env = (s.get("api") or {}).get("env")
        has_key = bool(os.getenv(env)) if env else None
        out.append({
            "id": sid,
            "name": s.get("name", sid),
            "enabled": s.get("enabled", True),
            "limit": s.get("limit"),
            "url": s.get("url"),
            "docs": s.get("docs"),
            "api_env": env,
            "api_required": (s.get("api") or {}).get("required", False),
            "has_key": has_key,            # True/False, ou None quando nao usa chave
            "last_count": st.get(sid, {}).get("count"),
            "last_run": st.get(sid, {}).get("when"),
        })
    return out


def _get_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _set_state(stats):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        data = _get_state()
        now = datetime.datetime.now().isoformat(timespec="seconds")
        for sid, cnt in stats.items():
            data[sid] = {"count": cnt, "when": now}
        with open(STATE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


# ----------------------------------------------------------------- formatador
def make_card(cve_id, date, score, vector, desc, source,
              keywords=None, type_="recent_vulnerability", usage=None):
    sev = "UNKNOWN"
    try:
        s = float(score)
        sev = ("CRITICAL" if s >= 9 else "HIGH" if s >= 7 else
               "MEDIUM" if s >= 4 else "LOW")
    except Exception:
        s = None
    kw = keywords or f"{cve_id} new exploit recent"
    usage = usage or ("Vulnerabilidade recente. Verifique se o software do alvo "
                      "corresponde a descricao.")
    return f"""
=== THREAT INTEL CARD ===
ID: {cve_id}
TYPE: {type_}
DATE: {date}
SEVERITY: {sev} (Score: {score if score not in (None, '') else 'N/A'})
VECTOR: {vector or 'N/A'}
KEYWORDS: {kw}
DESCRIPTION: {desc}
SOURCE: {source}
USAGE_NOTE: {usage}
=========================
"""


def _av_from_vector(vec):
    if not vec or "AV:" not in vec:
        return "N/A"
    try:
        letter = vec.split("AV:")[1][0].upper()
        return AV_MAP.get(letter, "N/A")
    except Exception:
        return "N/A"


# ----------------------------------------------------------------- coletores
def collect_nvd(limit=40, api_key=None):
    end = datetime.datetime.utcnow()
    start = end - datetime.timedelta(days=WINDOW_DAYS)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt),
        "cvssV3Severity": "CRITICAL", "resultsPerPage": int(limit), "noRejected": "",
    }
    headers = dict(UA)
    if api_key:
        headers["apiKey"] = api_key
    cards, ids = [], []
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                     params=params, headers=headers, timeout=30)
    r.raise_for_status()
    for item in r.json().get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id", "UNKNOWN")
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "No description.")
        score = vector = "N/A"
        try:
            md = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
            score = md.get("baseScore", "N/A")
            vector = md.get("attackVector", "N/A")
        except Exception:
            pass
        cards.append(make_card(cid, cve.get("published", "")[:10], score, vector,
                               desc, "NVD Recent Feed"))
        ids.append(cid)
    return cards, ids


def collect_circl(limit=30):
    cards, ids = [], []
    r = requests.get("https://cve.circl.lu/api/last", headers=UA, timeout=30)
    r.raise_for_status()
    for rec in r.json():
        if not isinstance(rec, dict):
            continue
        aliases = rec.get("aliases") or []
        cve_id = next((a for a in aliases if str(a).startswith("CVE-")),
                      rec.get("id"))
        if not cve_id:
            continue
        desc = (rec.get("details") or "").strip().replace("\n", " ")
        if not desc:
            continue
        vector = "N/A"
        sev = rec.get("severity") or []
        if sev and isinstance(sev, list):
            vec = sev[0].get("score", "")  # no CIRCL, 'score' e o vetor CVSS
            vector = _av_from_vector(vec)
        cards.append(make_card(cve_id, (rec.get("published") or "")[:10],
                               "N/A", vector, desc[:600],
                               "CIRCL CVE Search", keywords=f"{cve_id} {' '.join(aliases[:3])}"))
        if str(cve_id).startswith("CVE-"):
            ids.append(cve_id)
        if len(cards) >= int(limit):
            break
    return cards, ids


def _cvss_from_cve5(rec):
    for cont in [rec.get("containers", {}).get("cna", {})] + \
                list(rec.get("containers", {}).get("adp", []) or []):
        for m in (cont.get("metrics", []) or []):
            for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                if key in m:
                    cd = m[key]
                    return cd.get("baseScore", "N/A"), (cd.get("attackVector")
                                                        or _av_from_vector(cd.get("vectorString", "")))
    return "N/A", "N/A"


def collect_mitre(ids, limit=15, api_key=None):
    headers = dict(UA)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    cards = []
    seen = []
    for cid in ids:
        if len(cards) >= int(limit):
            break
        if cid in seen:
            continue
        seen.append(cid)
        try:
            r = requests.get(f"https://cveawg.mitre.org/api/cve/{cid}",
                             headers=headers, timeout=20)
            if r.status_code != 200:
                continue
            rec = r.json()
            cna = rec.get("containers", {}).get("cna", {})
            desc = next((d["value"] for d in cna.get("descriptions", [])
                         if d.get("lang", "").startswith("en")), "")
            if not desc:
                continue
            score, vector = _cvss_from_cve5(rec)
            date = (rec.get("cveMetadata", {}).get("datePublished") or "")[:10]
            cards.append(make_card(cid, date, score, vector, desc[:600],
                                   "CVE.org (MITRE CVE Services)"))
        except Exception:
            continue
    return cards, seen


# ----------------------------------------------------------------- orquestracao
def collect_all(sources=None):
    _load_dotenv()
    cfg = load_sources()
    cards, stats, recent_ids = [], {}, []

    def key_for(sid):
        env = (cfg[sid].get("api") or {}).get("env")
        return os.getenv(env) if env else None

    # 1) Fontes com feed proprio (descobrem IDs recentes).
    if cfg.get("nvd", {}).get("enabled") and (sources is None or "nvd" in sources):
        try:
            c, ids = collect_nvd(cfg["nvd"]["limit"], key_for("nvd"))
            cards += c; recent_ids += ids; stats["nvd"] = len(c)
            print(f"[CVE] NVD: {len(c)} cards")
        except Exception as e:
            stats["nvd"] = 0; print(f"[CVE] NVD falhou: {e}")

    if cfg.get("circl", {}).get("enabled") and (sources is None or "circl" in sources):
        try:
            c, ids = collect_circl(cfg["circl"]["limit"])
            cards += c; recent_ids += ids; stats["circl"] = len(c)
            print(f"[CVE] CIRCL: {len(c)} cards")
        except Exception as e:
            stats["circl"] = 0; print(f"[CVE] CIRCL falhou: {e}")

    # 2) MITRE enriquece os IDs recentes achados acima.
    if cfg.get("mitre", {}).get("enabled") and (sources is None or "mitre" in sources):
        try:
            c, _ = collect_mitre(recent_ids, cfg["mitre"]["limit"], key_for("mitre"))
            cards += c; stats["mitre"] = len(c)
            print(f"[CVE] MITRE: {len(c)} cards (enriquecimento)")
        except Exception as e:
            stats["mitre"] = 0; print(f"[CVE] MITRE falhou: {e}")

    return cards, stats


def update_file(sources=None):
    cards, stats = collect_all(sources)
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(cards))
    _set_state(stats)
    total = sum(stats.values())
    print(f"[CVE] {total} cards salvos em {OUTPUT_FILE} | por fonte: {stats}")
    return {"ok": total > 0, "total": total, "by_source": stats, "file": OUTPUT_FILE}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Coletor multi-fonte de CVEs")
    ap.add_argument("--sources", help="csv de fontes (nvd,circl,mitre)", default=None)
    ap.add_argument("--status", action="store_true", help="mostra status das fontes")
    a = ap.parse_args()
    if a.status:
        print(json.dumps(status(), indent=2))
    else:
        srcs = a.sources.split(",") if a.sources else None
        print(json.dumps(update_file(srcs), indent=2))
