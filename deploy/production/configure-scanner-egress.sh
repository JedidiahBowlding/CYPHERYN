#!/bin/sh
set -eu

network_name="${CYPHERYN_SCANNER_NETWORK:-cypheryn-egress-owned-targets}"
subnet="${CYPHERYN_SCANNER_SUBNET:-172.31.250.0/24}"
target_ip="${CYPHERYN_AUTHORIZED_TARGET_IP:?Set CYPHERYN_AUTHORIZED_TARGET_IP}"

case "$target_ip" in
  *[!0-9.]*|'')
    echo "authorized target must be an IPv4 address" >&2
    exit 64
    ;;
esac

if ! docker network inspect "$network_name" >/dev/null 2>&1; then
  docker network create \
    --driver bridge \
    --subnet "$subnet" \
    --label cypheryn.egress-policy=enforced \
    "$network_name" >/dev/null
fi

remove_rule() {
  while iptables -C DOCKER-USER "$@" 2>/dev/null; do
    iptables -D DOCKER-USER "$@"
  done
}

# Rules are source-scoped to the dedicated scanner subnet. Scanner containers
# may establish HTTPS/HTTP connections only to the explicitly authorized host;
# replies are permitted and every other forwarded destination is rejected.
remove_rule -s "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
remove_rule -s "$subnet" -d "$target_ip/32" -p tcp -m multiport --dports 80,443 -j ACCEPT
remove_rule -s "$subnet" -j REJECT --reject-with icmp-port-unreachable

# Recreate the ordered policy on every run so service restarts cannot leave an
# earlier catch-all reject ahead of the destination allow rule.
iptables -A DOCKER-USER -s "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A DOCKER-USER -s "$subnet" -d "$target_ip/32" -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A DOCKER-USER -s "$subnet" -j REJECT --reject-with icmp-port-unreachable

echo "CYPHERYN scanner egress is restricted to $target_ip on TCP 80/443"
