FROM metasploitframework/metasploit-framework:latest
WORKDIR /usr/src/metasploit-framework
EXPOSE 55553
ENTRYPOINT ["sh", "-c"]
CMD ["bundle exec ruby msfrpcd -f -S -U msf -P msfpass -a 0.0.0.0 -p 55553"]
