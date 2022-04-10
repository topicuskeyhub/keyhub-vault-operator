# Using KeyHub as secret store

## Secret synchronization

Every Kubernetes cluster runs a `keyhub-secrets-controller`, which is responsible for syncing secrets from KeyHub to Kubernetes. Secrets will be automatically synchronized with a 10 minute interval. In case of an error the retry interval is 2 minutes.

To define a mapping between KeyHub and Kubernetes a `KeyHubSecret` CR can be created. The name of the generated Kubernetes `Secret` is the same as the name of the `KeyHubSecret`. The mapping between a secret key and a vault record is based on the uuid of the vault record, e.g.:
```yaml
apiVersion: keyhub.topicus.nl/v1alpha1
kind: KeyHubSecret
metadata:
  name: "<name of the secret>"
spec:
  data:
    - name: "<secret key1>"
      record: "<KeyHub vault record uuid>"
      property: "username"
    - name: "<secret key2>"
      record: "<KeyHub vault record uuid>"
      property: "password"
```

The example above will create the following `Secret`:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: "<name of the secret>"
type: Opaque
data:
  <secret key1>: "<username from KeyHub vault record with uuid>"
  <secret key2>: "<password from KeyHub vault record with uuid>"
```

Supported property values are `username`, `password`, `link`, `file` and `lastModifiedAt`. The default property is `password`. Timestamps are returned in utc according to RFC3339 format. The keys in the following example will both expose the password field from the KeyHub vault record:
```yaml
apiVersion: keyhub.topicus.nl/v1alpha1
kind: KeyHubSecret
metadata:
  name: "<name of the secret>"
spec:
  data:
    - name: "<secret key1>"
      record: "<KeyHub vault record uuid>"
      property: "password"
    - name: "<secret key2>"
      record: "<KeyHub vault record uuid>"
```

The bcrypt password-hashing function can be used to hash the value of a password field before
it is stored in the resulting `Secret`:

```yaml
apiVersion: keyhub.topicus.nl/v1alpha1
kind: KeyHubSecret
metadata:
  name: "<name of the secret>"
spec:
  data:
    - name: "<secret key1>"
      record: "<KeyHub vault record uuid>"
      property: "password"
      format: "bcrypt"
```

Sometimes secrets are embedded in a configuration file, which is mounted into the pod. In this case the entire configuration file can be uploaded to KeyHub and exposed using `file` as property value.
```yaml
apiVersion: keyhub.topicus.nl/v1alpha1
kind: KeyHubSecret
metadata:
  name: "<name of the secret>"
spec:
  data:
    - name: "config.yaml"
      record: "<KeyHub vault record uuid>"
      property: "file"
```

The previous examples all create a secret with type `Opaque`. To create different types of secrets the Kubernetes secret `type` can be defined, e.g.:
```yaml
apiVersion: keyhub.topicus.nl/v1alpha1
kind: KeyHubSecret
metadata:
  name: "<name of the secret>"
spec:
  template:
    type: kubernetes.io/tls
  ...
```

### Basic authentication
A `kubernetes.io/basic-auth` secret uses the username and password fields from the vault record. E.g.:
```yaml
apiVersion: keyhub.topicus.nl/v1alpha1
kind: KeyHubSecret
metadata:
  name: "<name of the secret>"
spec:
  template:
    type: kubernetes.io/basic-auth
  data:
    - name: "auth"
      record: "<KeyHub vault record uuid>"
```

### SSH authentication
A `kubernetes.io/ssh-auth` secret requires a PEM formatted file containing just the private-key. E.g.:
```yaml
apiVersion: keyhub.topicus.nl/v1alpha1
kind: KeyHubSecret
metadata:
  name: "<name of the secret>"
spec:
  template:
    type: kubernetes.io/ssh-auth
  data:
    - name: "key"
      record: "<KeyHub vault record uuid>"
```

### TLS Secrets

#### Using multiple KeyHub vault records

If the certificate and key are stored in different vault records, they have to be added using the names `tls.crt` and `tls.key`, e.g.:
```yaml
apiVersion: keyhub.topicus.nl/v1alpha1
kind: KeyHubSecret
metadata:
  name: "<name of the secret>"
spec:
  template:
    type: kubernetes.io/tls
  data:
    - name: "tls.crt"
      record: "<KeyHub crt vault record uuid>"
    - name: "tls.key"
      record: "<KeyHub key vault record uuid>"
```

Optionally a CA certificate chain can be defined with the `ca.crt` field. The CA certificate chain will be included in the `tls.crt` field, after the leaf certificate.

```yaml
  data:
    - name: "ca.crt"
      record: "<KeyHub key vault record uuid>"
```

#### Using a single KeyHub vault record

To store the certificate and key in a single vault record, they have to be included in a certificate container. Currently the `PEM` and `PKCS#12` container formats are supported. The name field identifies the container format and has to be `pem` or `pkcs12`, e.g.:
```yaml
apiVersion: keyhub.topicus.nl/v1alpha1
kind: KeyHubSecret
metadata:
  name: "<name of the secret>"
spec:
  template:
    type: kubernetes.io/tls
  data:
    - name: "pem"
      record: "<KeyHub pem vault record uuid>"
```

The KeyHub password field is used to decrypt a password protected PKCS#12 file.

Both containers can contain a CA certificate chain. The CA certificate chain will be included in the `tls.crt` field, after the leaf certificate. The first certificate in the container is assumed to be the leaf certificate, and subsequent certificates, if any, are assumed to comprise the CA certificate chain.

To have a seperate field in the generated `Secret` resource containing the CA certificate chain, define the desired `Secret` field name in the `format` field. E.g. Traefik (2.2+) uses the `tls.ca` field:

```yaml
  data:
    - name: "ca.crt"
      record: "<KeyHub key vault record uuid>"
      format: tls.ca
```

### Labels and annotations
Helm [standard labels](https://helm.sh/docs/chart_best_practices/labels/#standard-labels) set on the `KeyHubSecret` CR are automatically set on the generated secret.

To overwrite standard labels or to set custom labels and annotations on the generated secret use the metadata field of the spec template, e.g.:
```yaml
apiVersion: keyhub.topicus.nl/v1alpha1
kind: KeyHubSecret
metadata:
  name: "<name of the secret>"
spec:
  template:
    metadata:
      labels:
        app: foo
      annotations:
        key1: value1
  data:
    - name: "my_secret"
      record: "<KeyHub vault record uuid>"
```

The generated secret is:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: "<name of the secret>"
  labels:
    app: foo
  annotations:
    key1: value1
type: Opaque
data:
  my_secret: ...
```

## Synchronization status
The sync status of a `KeyHubSecret` CR can be inspected with `kubectl`:
```console
$ kubectl get keyhubsecrets.keyhub.topicus.nl
NAMESPACE              NAME                                SYNC STATUS
default                example                             Synced
```

Creation, updates and errors during synchronization are written to the Kubernetes event log, e.g.:
```console
$ kubectl get events
LAST SEEN   TYPE      REASON            OBJECT                            MESSAGE
10s         Normal    SecretUpdated     keyhubsecret/example              Secret has been updated
14s         Normal    SecretCreated     keyhubsecret/ssh-example          Secret (type 'kubernetes.io/ssh-auth') has been created
1m20s       Warning   ProcessingError   keyhubsecret/tls-example          Unsupported secret type: kubernetes.io/tsl
30m         Warning   ProcessingError   keyhubsecret/auth-example         Missing KeyHub vault record(s)
```

More status details can be found on each `KeyHubSecret` CR, e.g.:
```console
$ kubectl describe keyhubsecrets.keyhub.topicus.nl example
...
Status:
  Secret Key Statuses:
    Hash:  <bcrypt hash of the value to detect drift>
    Key:   <referenced key>
  Sync:
    Status:  Synced
  Vault Record Statuses:
    Last Modified At:  <KeyHub record modification timestamp>
    Name:              <KeyHub record name>
    Record ID:         <KeyHub record UUID>
```
