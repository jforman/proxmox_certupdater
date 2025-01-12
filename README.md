# README

# Description

Using certmanager provided TLS certificats from Lets Encrypt, update the TLS certificates used by Proxmox nodes for HTTPS management.

# Requirements

* docker, for testing
* kubernetes, at least version 1.21
* cert-manager: https://cert-manager.io/
* proxmox and api credentials created

# Usage
## Kubernetes

### certificate yaml

```yaml
---
# https://cert-manager.io/docs/reference/api-docs/#cert-manager.io%2fv1
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: proxmox-local-lan
  namespace: default
spec:
  secretName: proxmox-local-lan-tls
  dnsNames:
  - proxmox.local.lan
  - pve1.local.lan
  - pve2.local.lan
  issuerRef:
    kind: ClusterIssuer
    name: letsencrypt-issuer-prod
```

I have requested a certificate with multiple DNS names on it. Why? proxmox.local.lan is a virtual IP shared among keepalived and haproxy, which provides TCP loadbalancing between the pve hosts. This way I can acess the cluster via https://proxmox.local.lan or via the node-specific https://pve1.local.lan FQDNs using the same certificate.

### cronjob yaml

```yaml
---
# https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/
apiVersion: batch/v1
kind: CronJob
metadata:
  name: certupdater-proxmox
  namespace: default
spec:
  schedule: "@weekly"
  successfulJobsHistoryLimit: 1
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app: certupdater-proxmox      
        spec:
          restartPolicy: Never
          containers:
          - name: certupdater-pve1
            image: jforman/proxmox_certupdater:latest
            imagePullPolicy: Always
            command:
            - ./certupdater.py
            args:
            - --auth=/proxmox-creds/proxmox-certupdater-apitoken.txt
            - --cert_dir=/certs
            - --destination=pve1.local.lan
            - --node=moon1
            volumeMounts:
            - name: proxmox-creds
              mountPath: "/proxmox-creds"
              readOnly: true
            - name: proxmox-certs
              mountPath: "/certs"
              readOnly: true            
          volumes:
          - name: proxmox-creds
            secret:
              secretName: proxmox-certupdater-api-key
          - name: proxmox-certs
            secret:
              secretName: proxmox-local-lan-tls
```

The pod running the container must have access to both the TLS certificates and the proxmox API key secrets in Kubernetes. 

Destination is an DNS name or IP address of the host running the PVE instance which the API call will be sent. Node is the name of the PVE name within the cluster.

### config

A simple configuration is needed to provide API access information to the Proxmox cluster. This information is configured in the Proxmox UI.

```
[default]
user = someuser@pve
id = sometoken
secret = someguid
```

# Notes

## Manually scheduling 

There might be instances where you want to manually execute a certificate push. To do such a thing, run

```
kubectl create job --from=cronjob/certupdater-proxmox certupdater-pve1
```
## Decode Secret

```
% ./kubectl --kubeconfig admin.conf get secret proxmox-tls -o json | \
    jq '.data."tls.crt"' | \
    base64 -di
```
