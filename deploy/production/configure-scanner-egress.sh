#!/bin/sh
set -eu

network_name="${CYPHERYN_SCANNER_NETWORK:-cypheryn-egress-owned-targets}"
subnet="${CYPHERYN_SCANNER_SUBNET:-172.31.250.0/24}"
authorized_ips="$(printf '%s' "${CYPHERYN_AUTHORIZED_TARGET_IPS:-${CYPHERYN_AUTHORIZED_TARGET_IP:-}}" | tr ',' ' ')"

if [ -z "$authorized_ips" ]; then
  echo "Set CYPHERYN_AUTHORIZED_TARGET_IPS (or legacy CYPHERYN_AUTHORIZED_TARGET_IP)" >&2
  exit 64
fi

for target_ip in $authorized_ips; do
  case "$target_ip" in
    *[!0-9.]*|'')
      echo "authorized target must be an IPv4 address: $target_ip" >&2
      exit 64
      ;;
  esac
done

if ! docker network inspect "$network_name" >/dev/null 2>&1; then
  docker network create \
    --driver bridge \
    --subnet "$subnet" \
    --label cypheryn.egress-policy=enforced \
    "$network_name" >/dev/null
fi

policy_chain="CYPHERYN-SCANNER-EGRESS"
iptables -N "$policy_chain" 2>/dev/null || true
iptables -F "$policy_chain"

# Remove the legacy inline rules and any earlier jump for this exact scanner
# subnet. A dedicated chain can then be atomically rebuilt without retaining a
# destination that was removed from the current authorization list.
iptables -S DOCKER-USER | while read -r operation chain remainder; do
  [ "$operation" = "-A" ] || continue
  [ "$chain" = "DOCKER-USER" ] || continue
  set -- $remainder
  case " $* " in
    *" -s $subnet "*) iptables -D DOCKER-USER "$@" ;;
  esac
done

# Rules are source-scoped to the dedicated scanner subnet. Scanner containers
# may establish HTTPS/HTTP connections only to explicitly authorized hosts;
# replies are permitted and every other forwarded destination is rejected.
iptables -A "$policy_chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for target_ip in $authorized_ips; do
  iptables -A "$policy_chain" -d "$target_ip/32" -p tcp -m multiport --dports 80,443 -j ACCEPT
done
iptables -A "$policy_chain" -j REJECT --reject-with icmp-port-unreachable
iptables -A DOCKER-USER -s "$subnet" -j "$policy_chain"

echo "CYPHERYN scanner egress is restricted to:$authorized_ips on TCP 80/443"
