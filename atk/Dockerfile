FROM metasploitframework/metasploit-framework:latest
WORKDIR /usr/src/metasploit-framework
EXPOSE 55553
# Senha do RPC configuravel via env (default compativel com o lab).
ENV MSF_RPC_PASSWORD=msfpass
ENTRYPOINT ["sh", "-c"]
CMD ["bundle exec ruby msfrpcd -f -S -U msf -P \"$MSF_RPC_PASSWORD\" -a 0.0.0.0 -p 55553"]
