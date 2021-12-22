# Decode Secret

```
% ./kubectl --kubeconfig admin.conf get secret proxmox-tls -o json | \
    jq '.data."tls.crt"' | \
    base64 -di
```