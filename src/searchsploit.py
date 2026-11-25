# -*- coding: utf-8 -*-
"""Integracao com o searchsploit (Exploit-DB).

Cobre os CVEs que o Metasploit NAO tem como modulo: dado produto/versao do
recon, procura PoCs standalone na base local do Exploit-DB (/opt/exploitdb).
O LLM (TIER C) copia um PoC com 'searchsploit -m <EDB-ID>' e o executa com
python3/perl/ruby/bash. Offline e best-effort: se o searchsploit nao estiver
instalado ou nao houver resultados, retorna vazio (nao quebra o pipeline).
"""
import json
import re
import shutil
import subprocess


def _major_version(terms):
    m = re.search(r"(\d+\.\d+)", terms or "")
    return m.group(1) if m else ""


def available():
    return shutil.which("searchsploit") is not None


def search(terms, limit=12, timeout=45):
    """Roda 'searchsploit -j <termos>' e devolve a lista de PoCs candidatos."""
    terms = (terms or "").strip()
    if not available() or not terms:
        return []
    try:
        r = subprocess.run(["searchsploit", "-j", "--disable-colour", terms],
                           capture_output=True, text=True, timeout=timeout)
        data = json.loads(r.stdout or "{}")
    except Exception:
        return []
    out = []
    for e in (data.get("RESULTS_EXPLOIT") or [])[:limit]:
        out.append({
            "title": e.get("Title", ""),
            "edb": e.get("EDB-ID", ""),
            "path": e.get("Path", ""),
            "type": e.get("Type", ""),
            "platform": e.get("Platform", ""),
        })
    return out


def search_text(terms, limit=12):
    """Resumo textual dos candidatos para injetar no prompt do LLM. Tenta os
    termos completos; se vazio, cai para produto + versao major.minor (ex.:
    'MySQL 5.0'), que e menos ruidoso que so o produto. Prioriza exploits de
    servico (remote/dos/local) sobre webapps, que costumam ser so apps que
    'mencionam' o produto no titulo."""
    terms = (terms or "").strip()
    cand = search(terms, limit=limit * 2)
    if not cand:
        parts = terms.split()
        prod = parts[0] if parts else ""
        mv = _major_version(terms)
        q2 = (prod + " " + mv).strip() if (prod and mv) else prod
        if q2 and q2 != terms:
            cand = search(q2, limit=limit * 2)
    if not cand:
        return ""
    order = {"remote": 0, "dos": 1, "local": 2}
    cand.sort(key=lambda c: order.get((c.get("type", "") or "").lower(), 3))
    cand = cand[:limit]
    lines = [f"- EDB-{c['edb']} [{c['platform']}/{c['type']}] {c['title']}"
             f"  (copy: searchsploit -m {c['edb']})" for c in cand]
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    q = " ".join(sys.argv[1:]) or "vsftpd 2.3.4"
    print(f"searchsploit disponivel: {available()}")
    print(search_text(q) or "(sem resultados)")
