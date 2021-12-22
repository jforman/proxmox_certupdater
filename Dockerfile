FROM python:3

WORKDIR /usr/src/app

COPY certupdater.py ./
COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

