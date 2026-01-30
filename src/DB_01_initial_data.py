# -*- coding: utf-8 -*-
import sys
import os
import re

# Ajusta path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from metasploit_client import MetasploitClient

def clean_msf_string(text):
    """Limpa lixo de classes Ruby do MSF para o RAG ficar limpo"""
    text = str(text)
    # Remove ['Msf::Module::Platform::...']
    text = re.sub(r"Msf::Module::Platform::", "", text)
    text = text.replace("['", "").replace("']", "").replace('["', '').replace('"]', '')
    return text

def format_module_card(mod_type, name, description, rank, arch, platform):
    """Cria o Card para o RAG"""
    desc_clean = str(description).strip().replace('\n', ' ').replace('\r', '')
    
    return f"""
=== METASPLOIT MODULE CARD ===
NAME: {mod_type}/{name}
TYPE: {mod_type}
RANK: {rank}
ARCH: {clean_msf_string(arch)}
PLATFORM: {clean_msf_string(platform)}
KEYWORDS: {name.replace('/', ' ')} {mod_type}
DESCRIPTION: {desc_clean}
OPTIONS:
Standard options (RHOSTS, RPORT). Check LHOST/LPORT for reverse shells.
USAGE_NOTE: Use this module when the target runs a service matching the name/description.
==============================
"""

def main():
    print("[DB_01] === GERADOR DE CONHECIMENTO MSF (BUSCA + DETALHES) ===")
    
    try:
        client = MetasploitClient(password="msfpass", server="192.168.70.20")
    except Exception as e:
        print(f"[ERRO] Falha conexao MSF: {e}")
        return

    # Lista Expandida de Termos
    search_terms = [
        "vsftpd", "samba", "distcc", "unreal_ircd", "postgresql", 
        "drb", "tomcat", "java_rmi", "nfs", "bind", "apache", 
        "telnet", "mysql", "proftpd", "ssh", "php", "manage/shell_to_meterpreter"
    ]
    
    unique_modules = set()
    cards = []
    
    print(f"[*] Iniciando mineracao profunda para {len(search_terms)} termos...")
    
    for term in search_terms:
        try:
            # ETAPA 1: BUSCA (Lista)
            search_res = client.client.call('module.search', [term])
            
            if not search_res or not isinstance(search_res, list):
                continue

            for item in search_res:
                fullname = item.get('fullname')
                rank = item.get('rank', 'normal')
                m_type = item.get('type')

                # Filtro de Qualidade
                if m_type not in ['exploit', 'auxiliary', 'post']: continue
                if rank not in ['excellent', 'great', 'good', 'normal']: continue
                if fullname in unique_modules: continue
                
                unique_modules.add(fullname)
                
                try:
                    m_type_clean, m_name_clean = fullname.split('/', 1)
                except:
                    continue

                # ETAPA 2: DETALHES (Info)
                try:
                    details = client.client.call('module.info', [m_type_clean, m_name_clean])
                    
                    if details:
                        description = details.get('description', 'No description found.')
                        arch = details.get('arch', 'unknown')
                        platform = details.get('platform', 'unknown')
                        
                        card = format_module_card(
                            m_type_clean, m_name_clean, description, rank, arch, platform
                        )
                        cards.append(card)
                        
                except Exception as e_det:
                    pass # Ignora erros pontuais de info

        except Exception as e:
            print(f"[!] Erro termo '{term}': {e}")

    # Salva
    output_path = "/app/config/ingest/metasploit_knowledge.txt"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(cards))
        
    print(f"\n[SUCESSO] Mineracao Concluida.")
    print(f"Total de Cards Gerados: {len(cards)}")
    print(f"Arquivo: {output_path}")

if __name__ == "__main__":
    main()