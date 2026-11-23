# Reusa a imagem do core (todas as deps do pipeline + rede do lab) e adiciona
# apenas as libs da Web UI. Evita reinstalar torch/sentence-transformers.
FROM ragsploit/core:latest
COPY webui/requirements.txt /tmp/webui-req.txt
RUN pip install --no-cache-dir -r /tmp/webui-req.txt
WORKDIR /app
EXPOSE 8090
CMD ["python", "src/web/app.py"]
