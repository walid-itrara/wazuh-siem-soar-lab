#!/bin/bash
touch /var/log/auth.log /var/log/nginx/access.log
chmod 666 /var/log/auth.log /var/log/nginx/access.log

# D?finir un mot de passe root complexe pour que sshd active bien la v?rification PAM/password
echo "root:Str0ngProdP@ssw0rd2026!" | chpasswd

nft flush ruleset
nft add table inet wazuh_active_response
nft add set inet wazuh_active_response attacker_blacklist '{ type ipv4_addr; }'
nft add chain inet wazuh_active_response input '{ type filter hook input priority 0; policy accept; }'
nft add rule inet wazuh_active_response input ip saddr @attacker_blacklist counter drop

/usr/sbin/sshd -E /var/log/auth.log -o LogLevel=INFO -o PermitRootLogin=yes -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=no
nginx

echo "[+] Production Server (172.28.10.10) services started: sshd, nginx, nftables"
python3 -u /opt/soar/wazuh_soar_agent.py
