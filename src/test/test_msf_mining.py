# -*- coding: utf-8 -*-
import sys
import os
import json
import time

# Ajusta o path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.metasploit_client import MetasploitClient

def main():
    print("=== TESTE DE MINERACAO PROFUNDA (SEARCH -> FILTER -> INFO) ===")
    
    try:
        client = MetasploitClient(password="msfpass", server="192.168.70.20")
        print("[OK] Conectado ao MSF RPC.")
    except Exception as e:
        print(f"[FATAL] Falha na conexao: {e}")
        return

    # Vamos testar com termos que sabemos que retornam resultados variados
    test_terms = ["vsftpd", "java_rmi"] 

    for term in test_terms:
        print(f"\n\n>>> [1. BUSCA RAPIDA] Termo: '{term}'")
        start_time = time.time()
        
        # Etapa 1: Busca a lista bruta
        try:
            candidates = client.client.call('module.search', [term])
        except Exception as e:
            print(f"[ERRO] Falha no search: {e}")
            continue
            
        duration = time.time() - start_time
        
        if not candidates:
            print(" [!] Nenhum resultado encontrado.")
            continue
            
        print(f" [i] Retornados {len(candidates)} candidatos em {duration:.2f}s")
        
        # Etapa 2: Filtragem e Detalhamento
        print(f">>> [2. FILTRO E DETALHAMENTO]")
        
        count_good = 0
        
        for item in candidates:
            # item = {'fullname': '...', 'rank': '...', 'type': '...'}
            
            fullname = item.get('fullname', '')
            rank = item.get('rank', 'normal')
            m_type = item.get('type', 'unknown')
            
            # --- FILTROS ---
            if m_type not in ['exploit', 'auxiliary']:
                # Ignora payloads, posts, encoders na busca inicial
                continue
            
            if rank not in ['excellent', 'great', 'good']:
                # Ignora exploits instaveis (normal, average, low)
                continue
            
            count_good += 1
            print(f"\n [CANDIDATO #{count_good}] {fullname} (Rank: {rank})")
            
            # Prepara para a chamada de Info
            try:
                # 'exploit/unix/ftp/vsftpd_234_backdoor' -> 'exploit', 'unix/ftp/vsftpd_234_backdoor'
                m_type_clean, m_name_clean = fullname.split('/', 1)
                
                # Etapa 3: Mineração Profunda (Pega a alma do exploit)
                print("   -> Buscando detalhes (module.info)...")
                details = client.client.call('module.info', [m_type_clean, m_name_clean])
                
                if details:
                    desc = details.get('description', 'N/A').strip()[:100].replace('\n', ' ') # Preview
                    arch = details.get('arch', 'unknown')
                    platform = details.get('platform', 'unknown')
                    
                    print(f"   [OK] CARD GERADO:")
                    print(f"        | Description: {desc}...")
                    print(f"        | Arch: {arch}")
                    print(f"        | Platform: {platform}")
                else:
                    print("   [!] Detalhes vazios.")
                    
            except Exception as e:
                print(f"   [ERRO] Falha ao pegar detalhes: {e}")
                
            # Limita a 2 exemplos por termo para não poluir o teste
            if count_good >= 2:
                print("   (Limitando teste a 2 itens por termo...)")
                break

if __name__ == "__main__":
    main()