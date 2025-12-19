FROM sagemath/sagemath:10.5

USER root
COPY server.sage .
COPY flag.py .
RUN sage --pip install pycryptodome
RUN apt-get update && apt-get install socat -y
CMD ["socat", "TCP-L:2468,fork,reuseaddr", "EXEC:'sage server.sage'"]