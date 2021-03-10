FROM python:3.7.7-slim-buster

RUN groupadd -g gpstcp && useradd -r -g gpstcp gpstcp

WORKDIR /gps-tcp
COPY ./* requirements.txt /gps-tcp/


RUN pip install --no-cache-dir -r requirements.txt

USER gpstcp

EXPOSE 5060
CMD ["python", "gps-server.py"]

