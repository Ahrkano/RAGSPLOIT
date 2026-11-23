# -*- coding: utf-8 -*-
"""
Gestao de wordlists de credenciais (.txt) para brute-force eficiente.

Formatos aceitos:
  - combo:  uma credencial por linha no formato user:pass
  - single: uma palavra por linha (tratada como SENHA)

resolve() consolida todas as wordlists habilitadas em arquivos que o
Metasploit le diretamente (USERPASS_FILE / USER_FILE+PASS_FILE), permitindo
rodar o login scanner UMA vez sobre a lista inteira (muito mais rapido que
iterar credencial a credencial em Python).

IMPORTANTE: os arquivos ficam em /app/data/wordlists, que deve estar montado
TAMBEM no container do Metasploit (atk) no mesmo caminho — o scanner le o
arquivo no host do MSF, nao no pipeline.
"""
import os
import re
import glob

WORDLIST_DIR = "/app/data/wordlists"
CACHE_DIR = os.path.join(WORDLIST_DIR, ".cache")
DEFAULT_COMBO = "/app/data/credentials.txt"
DEFAULT_USERS = ["root", "admin", "administrator", "msfadmin", "user",
                 "postgres", "sys", "service", "guest", "tomcat"]
MAX_ENTRIES = 20000  # teto de seguranca por arquivo gerado


def _ensure_dirs():
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)


def sanitize_name(name):
    base = os.path.basename(name or "").strip()
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if not base:
        base = "wordlist.txt"
    if not base.lower().endswith(".txt"):
        base += ".txt"
    return base


def _read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except Exception:
        return []


def classify(lines):
    if not lines:
        return "empty"
    with_colon = sum(1 for ln in lines if ":" in ln)
    return "combo" if with_colon >= len(lines) * 0.5 else "single"


def list_wordlists():
    """Lista a wordlist padrao + as adicionais em /app/data/wordlists."""
    _ensure_dirs()
    out = []
    files = []
    if os.path.exists(DEFAULT_COMBO):
        files.append(DEFAULT_COMBO)
    files += sorted(f for f in glob.glob(os.path.join(WORDLIST_DIR, "*.txt")))
    for path in files:
        lines = _read_lines(path)
        out.append({
            "name": os.path.basename(path),
            "path": path,
            "kind": classify(lines),
            "lines": len(lines),
            "size": os.path.getsize(path) if os.path.exists(path) else 0,
            "default": path == DEFAULT_COMBO,
        })
    return out


def add_wordlist(name, data):
    """Salva uma nova wordlist .txt. 'data' pode ser bytes ou str."""
    _ensure_dirs()
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="ignore")
    # valida: tem de ser texto com alguma linha util
    lines = [ln.strip() for ln in data.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("arquivo vazio ou sem linhas uteis")
    fname = sanitize_name(name)
    path = os.path.join(WORDLIST_DIR, fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return {"name": fname, "path": path, "kind": classify(lines), "lines": len(lines)}


def delete_wordlist(name):
    fname = sanitize_name(name)
    path = os.path.join(WORDLIST_DIR, fname)
    # nunca apaga a wordlist padrao
    if os.path.abspath(path) == os.path.abspath(DEFAULT_COMBO):
        return False
    if os.path.isfile(path):
        os.remove(path)
        return True
    return False


def resolve(selected=None):
    """Consolida wordlists em arquivos lidos pelo Metasploit.

    selected: lista de nomes a usar (None = todas). Retorna caminhos de
    USERPASS_FILE / USER_FILE / PASS_FILE (no caminho compartilhado com o atk)
    e estatisticas.
    """
    _ensure_dirs()
    combos = set()      # "user:pass"
    passwords = set()   # palavras soltas -> senhas
    users = set(DEFAULT_USERS)

    for wl in list_wordlists():
        if selected is not None and wl["name"] not in selected:
            continue
        lines = _read_lines(wl["path"])
        if wl["kind"] == "combo":
            for ln in lines:
                if ":" in ln:
                    u, p = ln.split(":", 1)
                    combos.add(f"{u}:{p}")
                    users.add(u)
        elif wl["kind"] == "single":
            for ln in lines:
                passwords.add(ln)

    userpass_file = user_file = pass_file = None
    if combos:
        # Metasploit USERPASS_FILE exige "usuario senha" separados por ESPACO
        # (nao por ':'), um par por linha.
        userpass_file = os.path.join(CACHE_DIR, "merged_userpass.txt")
        lines = []
        for c in list(combos)[:MAX_ENTRIES]:
            u, p = c.split(":", 1)
            lines.append(f"{u} {p}")
        with open(userpass_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    if passwords:
        pass_file = os.path.join(CACHE_DIR, "merged_pass.txt")
        with open(pass_file, "w", encoding="utf-8") as f:
            f.write("\n".join(list(passwords)[:MAX_ENTRIES]) + "\n")
        user_file = os.path.join(CACHE_DIR, "merged_users.txt")
        with open(user_file, "w", encoding="utf-8") as f:
            f.write("\n".join(list(users)[:MAX_ENTRIES]) + "\n")

    return {
        "userpass_file": userpass_file,
        "user_file": user_file,
        "pass_file": pass_file,
        "stats": {"combos": len(combos), "passwords": len(passwords),
                  "users": len(users)},
    }


if __name__ == "__main__":
    import json
    print("wordlists:", json.dumps(list_wordlists(), indent=2))
    print("resolve:", json.dumps(resolve(), indent=2))
