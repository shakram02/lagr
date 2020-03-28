FROM python:3.6 AS base
RUN apt-get update && apt-get install -y tftpd-hpa
#TODO change the server.config to be embedded in the Dockerfile 
COPY configs/server.config /etc/default/tftpd-hpa
RUN chown -R tftp /srv/tftp
RUN service tftpd-hpa restart && service tftpd-hpa status
COPY requirements.py /requirements.py
RUN pip install -r /requirements.py
ADD . /app
WORKDIR /app/

FROM base AS client
RUN apt-get update && apt-get install -y tftp