# kube-gen-certs
## Generate kubernetes certificates automatically for your ingresses using Vault's PKI functionality

### Cluster deployment
```bash
# Optional (hosted on docker hub)
$ make push REG="http://docker.astuart.co:5000" # e.g.

# Edit the dep.yml and/or copy to your personal manifest repo (you have one, right?)

# If you'd like to use configmaps and secrets for the configuration (as dep.yml does by default), then create them as follows, or from manifests wherever you store your config (again, a git repo, right??)

$ kubectl create secret generic vault-creds --from-literal=vault-token=${YOUR_VAULT_TOKEN}
$ kubectl create configmap vault --from-literal=addr=${YOUR_VAULT_ENDPOINT}

# Uncomment ROOT_CA environment var if vault uses a non-publicly-trusted CA for
# its own operation (probably, since that's the point)

$ kubectl create secret generic ca --from-file=ca.crt=${PATH_TO_YOUR_CA_CERT}

$ kubectl apply -f dep.yml
```

Usage of ./kube-gen-certs:
  -alsologtostderr
    	log to standard error as well as files
  -forcetls
    	force all ingresses to use TLS if certs can be obtained
  -incluster
    	the client is running inside a kuberenetes cluster
  -log_backtrace_at value
    	when logging hits line file:N, emit a stack trace
  -log_dir string
    	If non-empty, write log files in this directory
  -logtostderr
    	log to standard error instead of files
  -self-signed
    	self-sign all certificates
  -stderrthreshold value
    	logs at or above this threshold go to stderr
  -ttl string
    	the time to live for certificates (default "240h")
  -v value
    	log level for V logs
  -vault-role string
    	the vault role to use when obtaining certs (default "vault")
  -vmodule value
    	comma-separated list of pattern=N settings for file-filtered logging
