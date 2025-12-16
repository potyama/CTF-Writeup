FROM eclipse-temurin:24@sha256:d8100f03ed9fd3d1c7239b29e33f8ffe7b1268a70618d1d5074a30df202f4fd6

RUN apt-get -y update --fix-missing
RUN apt-get -y upgrade
RUN apt-get -y install socat

COPY Chall.java .
COPY flag.txt .
RUN javac Chall.java

CMD ["socat", "tcp-l:12348,reuseaddr,fork", "EXEC:'java Chall'"]