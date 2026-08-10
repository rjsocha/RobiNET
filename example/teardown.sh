#!/usr/bin/env bash
#
# Everything the demo created, including the state volumes: the instance, its
# authority, and every identity that registered.
set -eufo pipefail
IFS=$'\t\n'

cd "$(dirname "$0")"

for dir in ipv6 ipv4 tenant hub; do
  (cd "$dir" && docker compose down --volumes) || true
done

rm -rf tenant/secret hub/secret
printf '\ndown, and the keys with it\n'
