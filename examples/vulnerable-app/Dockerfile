# INTENTIONALLY VULNERABLE: EOL base image, runs as root, no healthcheck.
FROM python:3.6
ADD . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "app.py"]
