import os
import json
import datetime

LOOT_DIR = "/app/data/loot"

class LootManager:
    @staticmethod
    def _get_filepath(target_ip):
        # Garante que o diretorio existe
        os.makedirs(LOOT_DIR, exist_ok=True)
        # Cria um nome de arquivo unico por alvo
        return os.path.join(LOOT_DIR, f"loot_{target_ip}.json")

    @staticmethod
    def log_success(target_ip, module_name, session_info):
        """Cria o arquivo de loot inicial apos obter shell"""
        filepath = LootManager._get_filepath(target_ip)
        
        data = {
            "target": target_ip,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "PWNED",
            "method": module_name,
            "session": session_info,
            "evidence": {} # Comeca vazio, preenchido na Fase 4
        }
        
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        
        print(f"[$$$] LOOT INICIADO: {filepath}")

    @staticmethod
    def update_evidence(target_ip, command_name, output):
        """Atualiza o JSON existente com saida de comandos (Phase 4)"""
        filepath = LootManager._get_filepath(target_ip)
        
        if os.path.exists(filepath):
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                
                # Adiciona a evidencia
                data["evidence"][command_name] = output
                
                with open(filepath, "w") as f:
                    json.dump(data, f, indent=4)
                    
                print(f"[$$$] EVIDENCIA SALVA: {command_name}")
            except Exception as e:
                print(f"[ERRO LOOT] Falha ao atualizar evidencia: {e}")
        else:
            print(f"[ERRO LOOT] Tentativa de salvar evidencia sem shell previa para {target_ip}")