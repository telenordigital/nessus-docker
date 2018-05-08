#!/bin/sh

ACTIVATION_CODE=`cat /mnt/secrets/activation-code.txt`
ADMIN_PASSWORD=`cat /mnt/secrets/admin-password.txt`

# Install Nessus
dpkg -i /opt/nessus-manager/Nessus.deb

# Register with Tenable, also downloads plugins and necessary components
/opt/nessus/sbin/nessuscli fetch --register $ACTIVATION_CODE

# Add a default 'admin' user, the command is interactive...
empty -f -i in.fifo -o out.fifo /opt/nessus/sbin/nessuscli adduser admin
empty -w -i out.fifo -o in.fifo Login "$ADMIN_PASSWORD\n" # Login password
empty -w -i out.fifo -o in.fifo again "$ADMIN_PASSWORD\n" # Login password again
empty -w -i out.fifo -o in.fifo admin "y\n" # Should user be admin
empty -w -i out.fifo -o in.fifo rules "\n" # Ruleset for this user (RBAC)
empty -w -i out.fifo -o in.fifo ok "y\n" # Everything OK?

# Copy certificates to the correct location
cp /mnt/secrets/key.pem /opt/nessus/var/nessus/CA/serverkey.pem
cp /mnt/secrets/serverchain.pem /opt/nessus/com/nessus/CA/serverchain.pem
cp /mnt/secrets/cert.pem /opt/nessus/com/nessus/CA/servercert.pem

# Run service in the front
/opt/nessus/sbin/nessus-service
