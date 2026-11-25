# -*- coding: utf-8 -*-
"""
Reconhecimento eficiente de portas/servicos.

Usa nmap -sV (deteccao de servico/versao) quando disponivel — rapido e com
produto/versao/CPE, o que melhora muito a decisao do LLM e das politicas.
Se o nmap nao estiver instalado, cai para um connect-scan Python enxuto
(1 tentativa por porta, conjunto de portas reduzido) + banner grab.

Saida padronizada:
  { "21": {"port":21,"proto":"tcp","service":"ftp","product":"vsftpd",
           "version":"2.3.4","extrainfo":"","cpe":"...","banner":"..."}, ... }
"""
import os
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
import concurrent.futures

# Portas priorizadas no fallback (servicos classicos + metasploitable).
FALLBACK_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443, 445, 512,
                  513, 514, 1099, 1524, 2049, 2121, 3306, 3632, 5432, 5900,
                  6000, 6667, 6697, 8009, 8180, 8080, 8443, 9999]


def nmap_available():
    return shutil.which("nmap") is not None


def _nmap_scan(target, ports=None, extra_args=None):
    """nmap -sV em XML; retorna dict porta->info."""
    args = ["nmap", "-sV", "-T4", "--open", "-Pn", "-oX", "-"]
    if ports:
        args += ["-p", ports if isinstance(ports, str) else ",".join(map(str, ports))]
    else:
        args += ["--top-ports", "1000"]
    if extra_args:
        args += list(extra_args)
    args.append(target)
    out = subprocess.run(args, capture_output=True, text=True, timeout=600)
    result = {}
    if not out.stdout.strip():
        return result
    try:
        root = ET.fromstring(out.stdout)
    except ET.ParseError:
        return result
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            pid = port.get("portid")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            info = {"port": int(pid), "proto": proto, "service": "", "product": "",
                    "version": "", "extrainfo": "", "cpe": "", "banner": ""}
            if svc is not None:
                info["service"] = svc.get("name", "") or ""
                info["product"] = svc.get("product", "") or ""
                info["version"] = svc.get("version", "") or ""
                info["extrainfo"] = svc.get("extrainfo", "") or ""
                info["ostype"] = svc.get("ostype", "") or ""
                cpes = [c.text for c in svc.findall("cpe") if c.text]
                # CPE de aplicacao (cpe:/a:) p/ info; CPE de SO (cpe:/o:) p/ OS.
                info["cpe"] = next((c for c in cpes if not c.startswith("cpe:/o:")),
                                   (cpes[0] if cpes else ""))
                info["os_cpe"] = next((c for c in cpes if c.startswith("cpe:/o:")), "")
            # banner legivel consolidado
            info["banner"] = " ".join(
                x for x in [info["service"], info["product"], info["version"],
                            info["extrainfo"]] if x).strip() or "unknown"
            result[pid] = info
    return result


def _py_check_port(target, port, timeout=0.8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((target, port))
        s.close()
        return port if rc == 0 else None
    except Exception:
        return None


def _py_banner(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target, int(port)))
        try:
            b = s.recv(1024).decode("utf-8", errors="ignore").strip()
            if b:
                s.close()
                return re.sub(r"[^\x20-\x7E]", "", b)
        except socket.timeout:
            pass
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            b = s.recv(1024).decode("utf-8", errors="ignore").strip()
        finally:
            s.close()
        return re.sub(r"[^\x20-\x7E]", "", b) or "unknown"
    except Exception:
        return "unknown"


def _looks_http(info):
    """A porta JA parece HTTP pelo que o nmap retornou (service/banner)?"""
    svc = (info.get("service", "") or "").lower()
    b = (info.get("banner", "") or "").lower()
    return ("http" in svc or "www" in svc or "http" in b)


def _http_probe(target, port, timeout=3.0):
    """Sonda HTTP(S) de fallback: confirma se a porta fala HTTP mesmo quando o
    nmap NAO consegue fingerprintar (ex.: SPA/Node em porta nao-padrao que o
    -sV rotula 'ppp'). E deteccao MECANICA de protocolo pela RESPOSTA real
    (status line / headers / <title>), NAO um atalho hardcoded por porta.
    Retorna {service, banner, is_http, server, title, powered_by} ou None."""
    req = ("GET / HTTP/1.1\r\nHost: {h}\r\nUser-Agent: ragsploit-recon\r\n"
           "Accept: */*\r\nConnection: close\r\n\r\n").format(h=target)

    def _attempt(use_ssl):
        raw = None
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(timeout)
            raw.connect((target, int(port)))
            s = raw
            if use_ssl:
                import ssl
                s = ssl._create_unverified_context().wrap_socket(
                    raw, server_hostname=str(target))
            s.sendall(req.encode("latin-1", "ignore"))
            data = b""
            while len(data) < 16384:
                try:
                    chunk = s.recv(4096)
                except Exception:
                    break
                if not chunk:
                    break
                data += chunk
            s.close()
            return data
        except Exception:
            if raw is not None:
                try:
                    raw.close()
                except Exception:
                    pass
            return None

    def _parse(data, scheme):
        if not data:
            return None
        text = data.decode("latin-1", "ignore")
        if not re.match(r"HTTP/\d\.\d\s+\d{3}", text):
            return None
        head = text.split("\r\n\r\n", 1)[0]

        def _h(name):
            m = re.search(r"(?im)^" + re.escape(name) + r":\s*(.+?)\s*$", head)
            return m.group(1).strip() if m else ""

        server, powered = _h("Server"), _h("X-Powered-By")
        mt = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
        title = re.sub(r"\s+", " ", mt.group(1)).strip()[:80] if mt else ""
        extras = " ".join(x for x in [server, powered,
                          ("title: " + title) if title else ""] if x)
        banner = (scheme + (" " + extras if extras else "")).strip()
        return {"service": scheme, "is_http": True, "server": server,
                "title": title, "powered_by": powered, "banner": banner}

    # 1) HTTP em claro.
    data = _attempt(False)
    if data is not None:
        res = _parse(data, "http")
        if res:
            return res
        if data:  # recebeu dados mas nao e HTTP -> servico plaintext; nao tenta TLS
            return None
    # 2) TLS (a porta pode exigir handshake: https).
    return _parse(_attempt(True), "https")


def _enrich_http(target, ports_dict):
    """Pos-processa o recon: para cada porta aberta confirma HTTP(S) via sonda
    direta. Se o nmap JA identificou web, so marca is_http=True (preserva o
    banner rico do -sV). Se NAO (ex.: rotulo 'ppp'), re-rotula service=http(s) e
    enriquece o banner - isso destrava _is_web/enum-web/RAG no pipeline. E
    GENERICO: vale para servico web em qualquer porta/host, sem lista fixa."""
    if not ports_dict:
        return ports_dict

    def _probe(item):
        pid, info = item
        try:
            if _looks_http(info):
                info["is_http"] = True
                return
            res = _http_probe(target, pid)
            if res:
                info["service"] = res["service"]
                info["is_http"] = True
                info["banner"] = res["banner"]
                for k in ("server", "title", "powered_by"):
                    if res.get(k):
                        info[k] = res[k]
        except Exception:
            pass

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            list(ex.map(_probe, list(ports_dict.items())))
    except Exception:
        for it in list(ports_dict.items()):
            _probe(it)
    return ports_dict


def _py_scan(target, ports=None):
    ports = ports or FALLBACK_PORTS
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        futs = {ex.submit(_py_check_port, target, p): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r:
                found.append(r)
    result = {}
    for p in sorted(found):
        banner = _py_banner(target, p)
        result[str(p)] = {"port": p, "proto": "tcp", "service": "", "product": "",
                          "version": "", "extrainfo": "", "cpe": "", "banner": banner}
    return result


def infer_os(ports):
    """Deduz o SO do alvo a partir dos sinais do -sV (ostype, CPE de SO, produto,
    extrainfo, banner) agregados sobre todas as portas. Sem -O (nao exige raiz/
    raw sockets): usa o que a deteccao de servico ja revela. Retorna
    'Linux' | 'Windows' | 'unknown'."""
    text = " ".join(
        " ".join([i.get("ostype", ""), i.get("os_cpe", ""), i.get("product", ""),
                  i.get("extrainfo", ""), i.get("banner", "")]).lower()
        for i in (ports or {}).values())
    win = (text.count("windows") + text.count("microsoft")
           + text.count("cpe:/o:microsoft"))
    lin = (text.count("linux") + text.count("debian") + text.count("ubuntu")
           + text.count("unix") + text.count("cpe:/o:linux"))
    if win and win >= lin:
        return "Windows"
    if lin:
        return "Linux"
    return "unknown"


def scan(target, ports=None, prefer_nmap=True):
    """Ponto de entrada. Retorna dict porta->info. Usa nmap se disponivel."""
    if prefer_nmap and nmap_available():
        try:
            res = _nmap_scan(target, ports=ports)
            if res:
                _enrich_http(target, res)
                return {"method": "nmap", "ports": res, "os": infer_os(res)}
        except Exception as e:
            print(f"[RECON] nmap falhou ({e}); usando fallback Python.")
    pyres = _py_scan(target, ports=ports)
    _enrich_http(target, pyres)
    return {"method": "python", "ports": pyres, "os": infer_os(pyres)}


if __name__ == "__main__":
    import sys, json
    tgt = sys.argv[1] if len(sys.argv) > 1 else "192.168.70.30"
    print(json.dumps(scan(tgt), indent=2))
