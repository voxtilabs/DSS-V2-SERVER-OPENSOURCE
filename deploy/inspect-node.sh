#!/bin/bash
echo '=== OS ==='
lsb_release -ds 2>/dev/null || grep PRETTY /etc/os-release
uname -r
echo '=== node/npm ==='
node -v 2>/dev/null || echo NO_NODE
npm -v 2>/dev/null || echo NO_NPM
echo '=== docker ==='
docker --version 2>/dev/null || echo NO_DOCKER
docker compose version 2>/dev/null || echo NO_COMPOSE
echo '=== openssl ==='
openssl version
echo '=== ports ==='
for p in 1443 9100 18800 19800; do
  if ss -tlnH "sport = :$p" 2>/dev/null | grep -q .; then echo "$p BUSY-TCP";
  elif ss -ulnH "sport = :$p" 2>/dev/null | grep -q .; then echo "$p BUSY-UDP";
  else echo "$p FREE"; fi
done
echo '=== hw ==='
echo "cpus: $(nproc)"
free -h | awk 'NR==2'
df -h /home | tail -1
echo '=== ss failing? ==='
ss -v 2>/dev/null | head -1 || echo NO_SS