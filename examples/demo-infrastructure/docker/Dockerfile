FROM driftbeacon-demo-do-not-build.invalid/python:latest

USER root

ENV APP_ENV=demo

RUN apt-get update && apt-get install -y curl sudo

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 8080

CMD ["python", "/app/app.py"]
