#!/bin/bash
set -e

openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
    -keyout ca.key -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=CS6008/OU=Security/CN=CS6008 Root CA"

openssl req -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=CS6008/OU=ChatServer/CN=chat.server.local"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365
