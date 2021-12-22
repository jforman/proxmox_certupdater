#!/usr/local/bin/python
"""Wrapper around updating TLS certificates on a Proxmox VE node.

https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/certificates/custom
"""

import argparse
import base64
import configparser
import logging
import os
import sys
import time

from proxmoxer import ProxmoxAPI

parser = argparse.ArgumentParser(
    description="Update TLS certificate on a Proxmox VE node.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--auth", dest="auth_filepath",
                    default="/proxmox-auth.txt",
                    help="Config file containing Proxmox API authentication data.")
parser.add_argument("--debug", dest="debug", action='store_true')
parser.add_argument("--destination", dest="destination", help="Destination for sending API calls.")
parser.add_argument("--dry_run", action="store_true", help="Enable dry-run mode.")
parser.add_argument("--node", dest="node", help="Node name of Proxmox VE node.")
parser.add_argument("--cert_dir", dest="cert_dir", default="/cert",
                    help="Directory containing tls.{crt,key}.")
parser.add_argument("--update_wait_hours", dest="update_wait_hours", type=float, default=0,
                    help="Hours to sleep between certificate updates. 0 is one execution and quit.")
args = parser.parse_args()


def read_auth_file(fp):
    """read config file and return dict of auth parameters"""
    cfg = configparser.ConfigParser()
    logging.info(f"Reading Proxmox authentication information at {fp}.")
    cfg.read(fp)
    params = cfg.items('default')
    params_dict = dict(params)
    logging.debug(f'Config Parameters: {params_dict}.')
    return params_dict

def read_cert(cert_dir):
    """Read, decode, and return certificate data from directory."""
    logging.info(f'Reading certificate information in directory {cert_dir}.')
    cert = ""
    key = ""
    with open(os.path.join(cert_dir, "tls.crt"), 'r') as f:
        logging.info("Reading TLS cert.")
        cert = f.read()
    with open(os.path.join(cert_dir, "tls.key"), 'r') as f:
        logging.info("Reading TLS key.")
        key = f.read()

    logging.debug(f"tls.key: {key}")
    logging.debug(f"tls.crt: {cert}")
    return cert, key

def update_node(rpc_destination, node_name, auth_filepath, cert_dir):
    """Update node with contents of cert and key paths."""
    cert, key = read_cert(cert_dir)
    auth = read_auth_file(auth_filepath)
    p = ProxmoxAPI(
        rpc_destination,
        user=auth['user'],
        token_name=auth['id'],
        token_value=auth['secret'],
        verify_ssl=False)
    cert_options = {
        'certificates': cert,
        'node': node_name,
        'key': key,
        'force': 1,
        'restart': 1,
    }

    if args.dry_run:
        logging.info(f"DRY RUN: Will not actually call {rpc_destination} to update certificate for node {node_name}.")
        return
    logging.info(f'Calling {rpc_destination} to update TLS certificate for node {node_name}.')
    p_out = p.nodes(node_name).certificates.custom.post(**cert_options)
    logging.info(f'Certificate update output: {p_out}.')

def main():
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(format=f'%(asctime)s,%(process)d,%(levelname)s,node:{args.node},%(message)s', level=log_level)
    logging.info(f'Starting Proxmox Certupdater.')
    if args.update_wait_hours < 0:
        logging.error(f'Invalid duration: {args.update_wait_hours}. Value must be 0 or greater.')
        sys.exit(1)

    while True:
        update_node(args.destination, args.node, args.auth_filepath, args.cert_dir)
        if args.update_wait_hours == 0:
            sys.exit(0)
        logging.info(f"Sleeping {args.update_wait_hours} hours until next iteration.")
        time.sleep(3600 * args.update_wait_hours)

if __name__ == "__main__":
    main()
