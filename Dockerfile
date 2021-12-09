FROM python:3.9-slim-buster

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY start.sh .
COPY http-bridge http-bridge
COPY docs docs
COPY test_sample.py .

RUN chmod +x start.sh

EXPOSE 5060

CMD sleep 2; /start.sh