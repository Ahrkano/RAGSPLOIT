# -*- coding: utf-8 -*-
"""
Politica deterministica de estrategia (guardrail sobre o LLM).

Dado o servico/produto/versao (de preferencia do nmap -sV) e a disponibilidade
de wordlist, decide de forma objetiva QUANDO usar:
  - exploit_cve : ha match forte de produto+versao com vuln conhecida/backdoor;
  - brute_force : servico autenticavel e sem exploit forte, com wordlist;
  - enumeration : servico conhecido sem exploit forte nem auth (ou sem wordlist);
  - skip        : nada aplicavel.

O LLM continua propondo/refinando o modulo, mas esta politica fixa a ESCOLHA
entre modulo de exploit e brute-force, e fornece um modulo-base sugerido.
"""
import re

# Servicos autenticaveis -> login scanner do Metasploit.
LOGIN_MODULES = {
    "ftp": "auxiliary/scanner/ftp/ftp_login",
    "ssh": "auxiliary/scanner/ssh/ssh_login",
    "telnet": "auxiliary/scanner/telnet/telnet_login",
    "smb": "auxiliary/scanner/smb/smb_login",
    "netbios-ssn": "auxiliary/scanner/smb/smb_login",
    "microsoft-ds": "auxiliary/scanner/smb/smb_login",
    "mysql": "auxiliary/scanner/mysql/mysql_login",
    "postgresql": "auxiliary/scanner/postgres/postgres_login",
    "postgres": "auxiliary/scanner/postgres/postgres_login",
    "vnc": "auxiliary/scanner/vnc/vnc_login",
}

# Assinaturas de exploit forte: (regex sobre "product version banner") -> (modulo, razao)
EXPLOIT_SIGNATURES = [
    (r"vsftpd\s*2\.3\.4", "exploit/unix/ftp/vsftpd_234_backdoor",
     "vsftpd 2.3.4 contem backdoor (smiley) conhecido"),
    (r"unrealircd", "exploit/unix/irc/unreal_ircd_3281_backdoor",
     "UnrealIRCd 3.2.8.1 possui backdoor de comando"),
    (r"distcc", "exploit/unix/misc/distcc_exec",
     "distccd permite execucao remota de comando (CVE-2004-2687)"),
    (r"samba\s*3\.0\.2[0-5]", "exploit/multi/samba/usermap_script",
     "Samba 3.0.20-3.0.25 usermap_script RCE (CVE-2007-2447)"),
    (r"\bsamba\b", "exploit/multi/samba/usermap_script",
     "Samba potencialmente vulneravel a usermap_script (verificar versao)"),
    (r"mysql\s*5\.0", "auxiliary/scanner/mysql/mysql_login",
     "MySQL 5.0 — sem RCE direto; tentar login"),
]

# Scanners de enumeracao/versao por servico.
ENUM_MODULES = {
    "ftp": "auxiliary/scanner/ftp/ftp_version",
    "ssh": "auxiliary/scanner/ssh/ssh_version",
    "smtp": "auxiliary/scanner/smtp/smtp_version",
    "http": "auxiliary/scanner/http/http_version",
    "mysql": "auxiliary/scanner/mysql/mysql_version",
    "postgresql": "auxiliary/scanner/postgres/postgres_version",
    "smb": "auxiliary/scanner/smb/smb_version",
    "netbios-ssn": "auxiliary/scanner/smb/smb_version",
}


def decide(info, wordlist_available=True):
    """info: dict com service/product/version/banner. Retorna recomendacao."""
    service = (info.get("service") or "").lower()
    blob = " ".join(str(info.get(k, "")) for k in
                    ("service", "product", "version", "extrainfo", "banner")).lower()

    # 1) Exploit forte por assinatura de produto+versao.
    for pattern, module, reason in EXPLOIT_SIGNATURES:
        if re.search(pattern, blob):
            if module.startswith("exploit/"):
                return {"strategy": "exploit_cve", "module_type": "exploit",
                        "module_name": module, "confidence": "HIGH", "reason": reason}
            # assinatura que aponta para login (ex.: mysql 5.0)
            if wordlist_available:
                return {"strategy": "brute_force", "module_type": "auxiliary",
                        "module_name": module, "confidence": "MEDIUM", "reason": reason}

    # 2) Servico autenticavel -> brute-force (se houver wordlist).
    if service in LOGIN_MODULES and wordlist_available:
        return {"strategy": "brute_force", "module_type": "auxiliary",
                "module_name": LOGIN_MODULES[service], "confidence": "MEDIUM",
                "reason": f"Servico autenticavel '{service}' sem exploit forte; brute-force"}

    # 3) Enumeracao por serviço conhecido.
    if service in ENUM_MODULES:
        return {"strategy": "enumeration", "module_type": "auxiliary",
                "module_name": ENUM_MODULES[service], "confidence": "LOW",
                "reason": f"Servico '{service}' sem vuln forte; enumeracao de versao"}

    return {"strategy": "skip", "module_type": None, "module_name": None,
            "confidence": "LOW", "reason": "Sem estrategia aplicavel para o servico"}


def is_login_module(module_name):
    return bool(module_name) and ("login" in module_name or module_name in LOGIN_MODULES.values())
