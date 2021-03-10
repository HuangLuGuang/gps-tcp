FROM python:3.7.7-slim-buster

WORKDIR /gps-tcp
COPY requirements.txt /gps-tcp

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5060
CMD ["python", "gps-server.py"]
