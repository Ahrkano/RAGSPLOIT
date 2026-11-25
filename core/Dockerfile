FROM python:3.10-slim
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"
RUN apt-get update && apt-get install -y build-essential curl nano wget sshuttle socat git iputils-ping nmap \
    default-mysql-client postgresql-client smbclient snmp redis-tools netcat-traditional telnet ldap-utils openssl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY core/requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt
# Fase 2: Exploit-DB offline (searchsploit) p/ CVEs sem modulo no Metasploit.
# Apos o pip para manter a layer do pip (torch etc.) em cache. Clone raso (~1GB).
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && searchsploit -u >/dev/null 2>&1 || true
COPY src ./src
COPY config ./config
CMD ["sh", "-c", "python src/main_ingest.py || tail -f /dev/null"]
