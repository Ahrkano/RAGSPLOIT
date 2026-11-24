# Modulos externos do Metasploit (TIER B)

Esta arvore e montada no container `metasploit_atk` em `/root/.msf4/modules`
(ver `docker-compose.yml`). O Metasploit carrega `~/.msf4/modules`
automaticamente no startup — basta soltar um `.rb` na categoria certa e
recriar/reiniciar o `atk`:

```
data/msf_modules/
  exploits/<plataforma>/<nome>.rb     # ex.: exploits/linux/http/cve_xxxx.rb
  auxiliary/<categoria>/<nome>.rb
```

Uso: para CVEs recentes sem modulo oficial, coloque aqui o modulo da comunidade
(formato Metasploit). O pipeline tambem pode registrar em runtime via
`MetasploitClient.load_external_modules()` (loadpath + reload_all).

Nao versione exploits de terceiros sem revisar o conteudo.
