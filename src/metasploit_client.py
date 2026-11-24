# -*- coding: utf-8 -*-
from pymetasploit3.msfrpc import MsfRpcClient
import time
import re
import os

class MetasploitClient:
    def __init__(self, password=None, server=None, port=55553, max_retries=30):
        # Env tem precedencia sobre o argumento (fonte unica de verdade).
        password = os.getenv("MSF_RPC_PASSWORD") or password or "msfpass"
        server = os.getenv("MSF_RPC_HOST") or server or "192.168.70.20"
        print(f"[MSF] Conectando a {server}:{port}...")
        
        self.client = None
        self.cid = None
        self._verified = {}
        
        for attempt in range(max_retries):
            try:
                self.client = MsfRpcClient(password=password, server=server, port=port, ssl=False)
                self.cid = self.client.consoles.console().cid
                # Limpa o banner inicial ao criar o console
                self._flush_console()
                print(f"[MSF] SUCESSO: Conectado e Console RPC ({self.cid}) inicializado.")
                return 

            except Exception as e:
                wait_time = 4
                print(f"[MSF] Aguardando servico ({attempt+1}/{max_retries})...")
                time.sleep(wait_time)
        
        raise Exception(f"[MSF CRITICO] Timeout: Metasploit nao respondeu.")

    def _flush_console(self):
        """Le e descarta qualquer output pendente (banners)"""
        try:
            self.client.consoles.console(self.cid).read()
        except: pass

    def _clean_output(self, text):
        """
        Remove banners ASCII e formata o output para ser denso e util.
        Mantem apenas o que vem depois de 'https://metasploit.com' se o banner aparecer.
        """
        if not text: return ""

        # 1. Remove Banner ASCII (corta no link do rodape do banner)
        if "https://metasploit.com" in text:
            text = text.split("https://metasploit.com")[-1]

        # 2. Remove linhas vazias e espaços desnecessarios
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        
        # 3. Reconstroi o texto limpo
        return "\n".join(lines)

    def execute_command(self, command, timeout=20, done_marker=None):
        """Le o console ate concluir. Se done_marker for dado, encerra ao
        ve-lo na saida (ex.: login scanners imprimem "% complete"); senao,
        encerra quando o console fica ocioso (sem busy e sem dados novos).
        O flag busy e instavel logo apos o write, por isso a dupla checagem."""
        console = self.client.consoles.console(self.cid)
        console.write(command + "\n")
        data = ""
        elapsed = 0.0
        idle = 0
        time.sleep(0.5)
        while elapsed < timeout:
            output = console.read()
            chunk = output.get('data', '') or ''
            data += chunk
            if done_marker and done_marker in data:
                break
            busy = output.get('busy', False)
            if busy or chunk:
                idle = 0
            else:
                idle += 1
            if idle >= 3:
                break
            time.sleep(1.0)
            elapsed += 1.0
        return self._clean_output(data)

    def verify_module_exists(self, module_type, module_name):
        key = f"{module_type}/{module_name}"
        if key in self._verified:
            return self._verified[key]
        try:
            self.client.modules.use(module_type, module_name)
            ok = True
        except Exception:
            ok = False
        self._verified[key] = ok
        return ok

    def check_session(self):
        sessions = self.client.sessions.list
        if sessions:
            return list(sessions.keys())[0]
        return None

    def run_module(self, module_type, module_name, options):
        if not self.verify_module_exists(module_type, module_name):
            print(f"[MSF] ALERTA: Modulo {module_name} nao encontrado.")
            return None

        # O MSF valida o PAYLOAD contra o TARGET atual: definir PAYLOAD com um
        # TARGET incompativel falha ("Invalid payload for given target"). Por
        # isso ordenamos: TARGET primeiro, PAYLOAD depois, demais opcoes a seguir
        # (sort estavel preserva a ordem original dentro de cada grupo).
        def _rank(item):
            return {"TARGET": 0, "PAYLOAD": 1}.get(item[0].upper(), 2)

        ordered = sorted(options.items(), key=_rank)
        cmds = [
            f"use {module_type}/{module_name}",
            *[f"set {k} {v}" for k, v in ordered],
            "run -z"
        ]
        full_cmd = "\n".join(cmds)
        print(f"[MSF] Executando: {module_type}/{module_name}")
        return self.execute_command(full_cmd, timeout=20)

    def run_login_scanner(self, module_name, base_opts, userpass_file=None,
                          user_file=None, pass_file=None, timeout=240):
        """Login scanner eficiente: le a wordlist de ARQUIVO e roda UMA vez.
        Os arquivos precisam existir no host do MSF (volume compartilhado)."""
        mod = module_name.replace("auxiliary/", "").strip("/")
        if not self.verify_module_exists("auxiliary", mod):
            print(f"[MSF] Login scanner inexistente: {mod}")
            return None
        opts = dict(base_opts or {})
        if userpass_file: opts["USERPASS_FILE"] = userpass_file
        if user_file: opts["USER_FILE"] = user_file
        if pass_file: opts["PASS_FILE"] = pass_file
        opts.setdefault("STOP_ON_SUCCESS", "true")
        opts.setdefault("BLANK_PASSWORDS", "false")
        opts.setdefault("USER_AS_PASS", "true")
        opts.setdefault("VERBOSE", "false")
        opts.setdefault("BRUTEFORCE_SPEED", "4")
        cmds = [f"use auxiliary/{mod}"] + [f"set {k} {v}" for k, v in opts.items()] + ["run -z"]
        print(f"[MSF] Login scan (arquivo): auxiliary/{mod}")
        return self.execute_command("\n".join(cmds), timeout=timeout, done_marker="% complete")

    def search_modules(self, query, limit=25):
        """TIER A (modulo ausente): roda 'search <query>' no msfconsole e devolve
        a saida crua. Serve para alimentar o LLM com os NOMES REAIS de modulos
        desta instalacao (os nomes mudam entre versoes), em vez de ele adivinhar.
        """
        q = (query or "").strip()
        if not q:
            return ""
        out = self.execute_command(f"search {q}", timeout=40) or ""
        # limita as linhas para nao estourar o prompt do LLM
        lines = out.splitlines()
        if len(lines) > limit + 6:
            lines = lines[:limit + 6]
        return "\n".join(lines)

    def load_external_modules(self, path=None):
        """TIER B (modulo ausente): registra uma arvore de modulos externos/
        comunitarios (.rb) e re-indexa (loadpath + reload_all). O 'path' precisa
        existir no HOST do Metasploit (volume compartilhado). Best-effort: nao
        quebra o pipeline se o diretorio nao existir.
        """
        path = path or os.getenv("MSF_EXTRA_MODULES", "/root/.msf4/modules")
        try:
            out = self.execute_command(f"loadpath {path}", timeout=60) or ""
            low = out.lower()
            # Nada carregado (dir ausente/vazio) -> nao gasta tempo no reload_all.
            if ("does not exist" in low or "loaded 0 modules" in low
                    or "no modules" in low or "fail" in low):
                return out
            self.execute_command("reload_all", timeout=180)
            return out
        except Exception as e:
            return f"[loadpath erro] {e}"
