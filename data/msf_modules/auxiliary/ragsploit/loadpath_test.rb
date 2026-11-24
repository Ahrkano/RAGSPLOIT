##
# RAGSPLOIT - modulo externo de exemplo (verifica que ~/.msf4/modules carrega).
# Coloque aqui modulos .rb da comunidade (ex.: CVEs recentes sem modulo oficial),
# respeitando a arvore padrao do Metasploit:
#   data/msf_modules/exploits/<plataforma>/<nome>.rb
#   data/msf_modules/auxiliary/<categoria>/<nome>.rb
# O container metasploit_atk monta este diretorio em /root/.msf4/modules e o
# Metasploit o carrega automaticamente no startup.
##
class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'RAGSPLOIT External Module Loadpath Test',
      'Description' => %q{
        Modulo de exemplo para confirmar que a arvore de modulos externos
        (~/.msf4/modules, montada do repo) e carregada pelo Metasploit.
      },
      'Author'      => ['RAGSPLOIT'],
      'License'     => MSF_LICENSE))
  end

  def run
    print_good('RAGSPLOIT external module tree loaded and runnable.')
  end
end
