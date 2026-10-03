#!/bin/bash
TARGET="172.28.10.10"

echo "======================================================================"
echo "   CLIENT TESTER NODE (172.28.10.20) -> TARGET ($TARGET)              "
echo "======================================================================"
sleep 3

echo -e "\n[1/4] Testing baseline connectivity to $TARGET..."
HTTP_CODE=$(curl -s -o /dev/null -w "\%{http_code}" --connect-timeout 2 http://$TARGET/)
echo "    -> Baseline HTTP Status: $HTTP_CODE (Server Reachable)"
sleep 1

echo -e "\n[2/4] Sending Web SQL Injection attack signature..."
curl -s --connect-timeout 2 "http://$TARGET/login.php?id=1'%20OR%201=1--" > /dev/null || true
sleep 1

echo -e "\n[3/4] Performing SSH Brute-Force authentication tests (5 attempts)..."
for i in 1 2 3 4 5; do
    echo "    -> SSH attempt #$i/5 (user: root)..."
    timeout 3 sshpass -p "WrongPass$i" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 -o PreferredAuthentications=password -o PubkeyAuthentication=no root@$TARGET "exit" 2>/dev/null || true
    sleep 1
done

echo -e "\n[4/4] Verifying Kernel Firewall Drop (Active Response)..."
sleep 1
if curl -s --connect-timeout 3 http://$TARGET/ > /dev/null; then
    echo "    [!] Erreur: Le serveur repond encore."
else
    echo "    [SUCCESS] CONNECTION TIMED OUT! Kernel nftables a bien bloque 172.28.10.20!"
fi
echo "======================================================================"
