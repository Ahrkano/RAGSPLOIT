# -*- coding: utf-8 -*-
from pymetasploit3.msfrpc import MsfRpcClient
import time
import re

class MetasploitClient:
    def __init__(self, password, server="192.168.70.20", port=55553, max_retries=30):
        print(f"[MSF] Conectando a {server}:{port}...")
        
        self.client = None
        self.cid = None
        
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

    def execute_command(self, command, timeout=10):
        self.client.consoles.console(self.cid).write(command + "\n")
        data = ""
        elapsed = 0
        while elapsed < timeout:
            output = self.client.consoles.console(self.cid).read()
            if output['data']:
                data += output['data']
            
            # Se ja retornou o prompt do msf, provavelmente acabou
            if output.get('prompt'):
                break
                
            time.sleep(1)
            elapsed += 1
            
        return self._clean_output(data)

    def verify_module_exists(self, module_type, module_name):
        try:
            self.client.modules.use(module_type, module_name)
            return True
        except:
            return False

    def check_session(self):
        sessions = self.client.sessions.list
        if sessions:
            return list(sessions.keys())[0]
        return None

    def run_module(self, module_type, module_name, options):
        if not self.verify_module_exists(module_type, module_name):
            print(f"[MSF] ALERTA: Modulo {module_name} nao encontrado.")
            return None

        cmds = [
            f"use {module_type}/{module_name}",
            *[f"set {k} {v}" for k, v in options.items()],
            "run -z"
        ]
        full_cmd = "\n".join(cmds)
        print(f"[MSF] Executando: {module_type}/{module_name}")
        return self.execute_command(full_cmd, timeout=20)