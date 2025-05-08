# Demo of Flask in Docker with Gunicorn and nginx with HTTPS certificates

Flask: see <https://flask.palletsprojects.com/en/stable/>

Certs: see <https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https>

To generate local certs I ran
```bash
cd certs
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

To use,
```bash
make container_build
make up
```

In a browser, visit <https://localhost> to see a static HTML page


# Guide

This demo repo is part of a sequence of tutorials

![sequence of demos](https://raw.githubusercontent.com/allofphysicsgraph/pdg_essential_demo_docker/refs/heads/main/tutorials_dependency_graph.svg)

