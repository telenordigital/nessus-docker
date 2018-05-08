# Using Ubuntu since Nessus is packaged for either Ubuntu or CentOS/RHEL.
FROM ubuntu:16.04

ADD entrypoint.sh /entrypoint.sh
ADD Nessus.deb /opt/nessus-manager/Nessus.deb

## For testing purposes only, secrets should be accessed in another way when deploying
#ADD activation-code.txt /mnt/secrets/activation-code.txt
#ADD admin-password.txt /mnt/secrets/admin-password.txt

WORKDIR /opt/nessus-manager

RUN apt-get update && \
    apt-get -y install empty-expect && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 8834
CMD ["/entrypoint.sh"]
