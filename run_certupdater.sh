#!/bin/bash -x

# Args:
#   $1: Path of directory containing tls.{crt,key} files.
#   $2: Path to Proxmox authentication configuration.
#   $3*: Parameters to certupdater.py.

docker build -t jforman/proxmox_certupdater:latest .

docker run -it --rm \
    -v `realpath $1`:/cert:ro \
    -v `realpath $2`:/proxmox-auth.txt:ro \
    jforman/proxmox_certupdater:latest \
    ./certupdater.py ${@:3}
