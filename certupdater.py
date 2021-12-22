#!/usr/local/bin/python
"""Wrapper around updating TLS certificates on a Proxmox VE node.

https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/certificates/custom
"""

# TODO: proxmox authentication. reading in the API key (stored in a k8s secret)

import argparse
import base64
import configparser
import logging
import os
import sys
from proxmoxer import ProxmoxAPI

parser = argparse.ArgumentParser(
    description="Update TLS certificate on a Proxmox VE node.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--auth", dest="auth_filepath",
                    default="/proxmox-auth.txt",
                    help="Config file containing Proxmox API authentication data.")
parser.add_argument("--debug", dest="debug", action='store_true')
parser.add_argument("--destination", dest="destination", help="Destination for sending API calls.")
parser.add_argument("--node", dest="node", help="Node name of Proxmox VE node.")
parser.add_argument("--cert_dir", dest="cert_dir", default="/cert",
                    help="Directory containing tls.{crt,key}.")
parser.add_argument("--update-interval", dest="update_interval", type=float, default=0,
                    help="Duration in hours between certificate updates. 0 is one execution and quit.")
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
        cert = base64.b64decode(f.read())
    with open(os.path.join(cert_dir, "tls.key"), 'r') as f:
        key = base64.b64decode(f.read())

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

    logging.info(f'Calling {rpc_destination} to update TLS certificate for node {node_name}.')
    p_out = p.nodes(node_name).certificates.custom.post(**cert_options)
    logging.info(f'Certificate update output: {p_out}.')

def main():
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(format='%(asctime)s,%(levelname)s,%(message)s', level=log_level)
    logging.info(f'Starting Proxmox Certupdater.')
    if args.update_interval < 0:
        logging.error(f'Invalid duration: {args.update_interval}. Value must be 0 or greater.')
        sys.exit(1)

    while True:
        update_node(args.destination, args.node, args.auth_filepath, args.cert_dir)
        if args.update_interval == 0:
            sys.exit(0)
        logging.info('Sleeping {args.update_interval} hours until next iteration.')
        time.sleep(3600 * args.update_interval)

if __name__ == "__main__":
    main()
