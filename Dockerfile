FROM python:3.7.7-slim-buster

RUN groupadd -g 1000 gpstcp && useradd -u 1000 -g 1000 gpstcp

WORKDIR /gps-tcp
COPY --chown=gpstcp ./  /gps-tcp/


RUN pip install --no-cache-dir -r requirements.txt

USER gpstcp

EXPOSE 5060
CMD ["python", "gps-server.py"]

