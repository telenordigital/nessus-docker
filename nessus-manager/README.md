# Nessus Manager in Docker

This builds a Docker image for running and deploying Nessus Manager in a Docker container.
We deploy this using Terraform, where the image is pushed to AWS ECR.

## Build

1. Download a Nessus Manager deb package and place it in this repo as `Nessus.deb`
2. Build and run the container like so:

```
$ docker build -t nessus-manager:latest .
$ docker run -dp 8854 nessus-manager:latest
```

## Secrets

Secrets are expected to be available in the path `/mnt/secrets`, the expected secrets are:

Secret          | Purpose                         | Filename
--------------- | ------------------------------- | -------------------
Activation Code | To activate the Nessus Manager  | activation-code.txt
Admin password  | The password for the admin user | admin-password.txt
TLS Cert        | To allow HTTPS                  | key.pem
TLS Chain       | To allow HTTPS                  | serverchain.pem
Private Key     | To allow HTTPS                  | cert.pem

## Testing

1. Get a valid Nessus activation code and save it as `activation-code.txt` in this folder.
2. Write a admin password to the file `admin-password.txt` in this folder.
3. Uncomment the lines in the Dockerfile that adds the test secrets.
4. Build and run the image.
