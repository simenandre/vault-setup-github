# vault-setup-github

The `vault-setup-github` service automates the process of [configuring github authentication](https://www.vaultproject.io/docs/auth/github) on HashiCorp Vault instances running on [Google Cloud Platform](https://cloud.google.com).

It uses a root token stored in a Google Cloud Storage](https://cloud.google.com/storage) bucket, named `root-token.enc` and encrypted using [Google Cloud KMS](https://cloud.google.com/kms). Want that to _just happen_? Use [sethvargo/vault-init](https://github.com/sethvargo/vault-init).

This is a companion service too [sethvargo/vault-init](https://github.com/sethvargo/vault-init).

## Usage

The `vault-setup-github` service is designed to be run alongside a Vault server and
communicate over local host.

You can download the code and compile the binary with Go. Alternatively, a
Docker container is available via the Docker Hub:

```text
$ docker pull cobraz/vault-setup-github
```

To use this as part of a Kubernetes Vault Deployment:

```yaml
containers:
- name: vault-setup-github
  image: registry.hub.docker.com/cobraz/vault-setup-github:0.0.1
  imagePullPolicy: Always
  env:
  - name: GCS_BUCKET_NAME
    value: my-gcs-bucket
  - name: KMS_KEY_ID
    value: projects/my-project/locations/my-location/cryptoKeys/my-key
```

## Configuration

The vault-setup-github service supports the following environment variables for configuration:

- `GCS_BUCKET_NAME` - The Google Cloud Storage Bucket where the vault master key
  and root token is stored.

- `KMS_KEY_ID` - The Google Cloud KMS key ID used to encrypt and decrypt the
  vault master key and root token.

- `VAULT_SKIP_VERIFY` (false) - Disable TLS validation when connecting. Setting
  to true is highly discouraged.

- `GITHUB_ORGANIZATION` - Your Github organization (eg. tabetalt)

- `GITHUB_ADMIN_USER` - If applied, a user is added with `root` policy with the given name.

### Example Values

```
GCS_BUCKET_NAME="vault-storage"
KMS_KEY_ID="projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/key"
GITHUB_ORGANIZATION="tabetalt"
GITHUB_ADMIN_USER="cobraz"
```

### IAM &amp; Permissions

The `vault-setup-github` service uses the official Google Cloud Golang SDK. This means
it supports the common ways of [providing credentials to GCP][cloud-creds].

To use this service, the service account must have the following minimum
scope(s):

```text
https://www.googleapis.com/auth/cloudkms
https://www.googleapis.com/auth/devstorage.read_write
```

Additionally, the service account must have the following minimum role(s):

```text
roles/cloudkms.cryptoKeyEncrypterDecrypter
roles/storage.objectAdmin OR roles/storage.legacyBucketWriter
```

For more information on service accounts, please see the
[Google Cloud Service Accounts documentation][service-accounts].

[cloud-creds]: https://cloud.google.com/docs/authentication/production#providing_credentials_to_your_application
[service-accounts]: https://cloud.google.com/compute/docs/access/service-accounts
