#!/bin/sh
set -eu
if ! docker network inspect rea-fetch-isolated >/dev/null 2>&1; then
 docker network create --internal --subnet 172.30.44.0/28 rea-fetch-isolated
fi
iptables -N REA_FETCH_GUARD 2>/dev/null || true
iptables -C REA_FETCH_GUARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A REA_FETCH_GUARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C REA_FETCH_GUARD -d 172.30.44.1 -p tcp --dport 3182 -j ACCEPT 2>/dev/null || iptables -A REA_FETCH_GUARD -d 172.30.44.1 -p tcp --dport 3182 -j ACCEPT
iptables -C REA_FETCH_GUARD -j REJECT 2>/dev/null || iptables -A REA_FETCH_GUARD -j REJECT
iptables -C INPUT -s 172.30.44.0/28 -j REA_FETCH_GUARD 2>/dev/null || iptables -I INPUT 1 -s 172.30.44.0/28 -j REA_FETCH_GUARD
