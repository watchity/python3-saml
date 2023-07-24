FROM python:3.9
RUN apt update && apt install -y libxmlsec1-dev
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt