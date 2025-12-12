FROM python:3.13.5-alpine@sha256:37b14db89f587f9eaa890e4a442a3fe55db452b69cca1403cc730bd0fbdc8aaf as app

RUN pip install pycryptodome

FROM pwn.red/jail
COPY --from=app / /srv

RUN mkdir /srv/app

COPY chal.py /srv/app/run
COPY ./flag.txt /srv/app/

RUN chmod 555 /srv/app/run
RUN chmod 444 /srv/app/flag.txt

ENV JAIL_MEM=20M JAIL_TIME=300 JAIL_PORT=12349
EXPOSE 12349