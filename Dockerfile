FROM python:3.6
RUN apt-get update && apt-get install -y tftpd-hpa
COPY configs/server.config /etc/default/tftpd-hpa
RUN chown -R tftp /srv/tftp
RUN service tftpd-hpa restart && service tftpd-hpa status
COPY requirements.py /requirements.py
RUN pip install -r /requirements.py
# WORKDIR /app/submissions/extracted
ADD . /app