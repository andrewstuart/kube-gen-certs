# kube-gen-certs
## Generate kubernetes certificates automatically for your ingresses using
## Vault's PKI functionality

### Usage
```bash
$ make push REG="http://docker.astuart.co:5000" # e.g.

# Edit the dep.yml and/or copy to your personal manifest repo (you have one, right?)

# If you'd like to use configmaps and secrets for the configuration (as dep.yml does by default), then create them as follows, or from manifests wherever you store your config (again, a git repo, right??)

$ kubectl create secret generic vault-creds --from-literal=vault-token=${YOUR_VAULT_TOKEN}
$ kubectl create configmap vault --from-literal=addr=${YOUR_VAULT_ENDPOINT}

# Uncomment ROOT_CA environment var if vault uses a non-publicly-trusted CA for its own operation (probably, since that's the point)

$ kubectl create secret generic ca --from-file=ca.crt=${PATH_TO_YOUR_CA_CERT}

$ kubectl apply -f dep.yml
```
