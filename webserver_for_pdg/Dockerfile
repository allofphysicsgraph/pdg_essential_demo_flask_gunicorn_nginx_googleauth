# Physics Derivation Graph
# Ben Payne, 2025
# https://creativecommons.org/licenses/by/4.0/
# Attribution 4.0 International (CC BY 4.0)


# https://docs.docker.com/engine/reference/builder/#from
# https://github.com/phusion/baseimage-docker
FROM phusion/baseimage:focal-1.1.0

WORKDIR /code
ENV FLASK_APP=pdg_app.py
ENV FLASK_RUN_HOST=0.0.0.0

RUN apt-get update && \
    apt-get install -y \
               vim \
               python3 \
               python3-pip \
               python3-dev 

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

# TODO: don't be root!

#EXPOSE 5000

COPY . .

#CMD ["flask", "run"]

#EOF
