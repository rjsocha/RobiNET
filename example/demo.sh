#!/usr/bin/env bash
#
# The whole thing on one machine, walked through rather than performed: it
# brings up the parts that are somebody else's job, and stops at every point
# where a person decides something.
#
# Linux only. ./teardown.sh removes everything, including the keys.
set -eufo pipefail
IFS=$'\t\n'

cd "$(dirname "$0")"

say()  { printf '\n\033[1m== %s\033[0m\n\n' "$1"; }
tell() { printf '   %s\n' "$1"; }
cmd()  { printf '\n     %s\n\n' "$1"; }

pause() {
  if [ -t 0 ]; then
    printf '   [enter] '
    read -r _
  fi
}

# waitfor runs a command until it says yes, or gives up. A demo that carried on
# regardless would show an empty table where the interesting part belongs.
waitfor() {
  local what=$1 tries=$2
  shift 2

  printf '   waiting for %s' "$what"
  for _ in $(seq "$tries"); do
    if "$@" >/dev/null 2>&1; then
      printf '\n\n'
      return 0
    fi
    printf '.'
    sleep 2
  done

  printf '\n'
  return 1
}

pending_arrived() { ./robinet member pending 2>/dev/null | grep -q connector; }
admitted()        { ./robinet reach 2>/dev/null | grep -q robinet; }

example=${1:-ipv4}
case "$example" in
  ipv4|ipv6) ;;
  *) printf 'usage: %s [ipv4|ipv6]\n' "$0"; exit 2 ;;
esac

say "what this is"
tell "A hub, your own daemon, and a compose project with a database that"
tell "publishes no port. By the end you reach that database by name from"
tell "outside its network, and nothing was exposed to do it."
tell ""
tell "This example carries $example."
pause

say "1. the hub, which is somebody else's job"

mkdir -p tenant/secret hub/secret/binder
if [ ! -f tenant/secret/tenant_ed25519 ]; then
  ssh-keygen -t ed25519 -f tenant/secret/tenant_ed25519 -N '' -C tenant@robinet >/dev/null
fi
{
  printf 'binder:\n  - name: demo\n    key:\n      - "%s"\n' "$(cat tenant/secret/tenant_ed25519.pub)"
} > hub/secret/binder/demo.yaml

(cd hub && docker compose up -d >/dev/null 2>&1)

tell "Running on 250.250.250.250. It holds no signing key and decides nothing;"
tell "it carries requests and keeps the route table. Your ssh key is what it"
tell "knows you by, and it was just written into its configuration."
cmd "cd hub && docker compose logs | tail"
pause

say "2. your machine joins it"

(cd tenant && docker compose down >/dev/null 2>&1 || true)
(cd tenant && docker compose run --rm --no-deps tenant join \
  --hub https://250.250.250.250:8443 --token demo --insecure \
  --state /data/tenant.json --ssh-key /run/secrets/binder_key \
  --name tenant-demo --no-setup >/dev/null 2>&1) || true
(cd tenant && docker compose up -d >/dev/null 2>&1)
sleep 2

tell "Registered and running. Everything from here goes through ./robinet,"
tell "which is just docker compose exec into that container."
cmd "./robinet status"
pause

say "3. an instance of your own"

./robinet instance create --name example --shared-token demo >/dev/null 2>&1 || true
./robinet instance show example | sed 's/^/   /'

tell ""
tell "You own it. Its certificate authority was generated on your machine and"
tell "never left it - the hub cannot issue anything for this instance, and"
tell "nobody but you can admit anybody to it."
pause

say "4. a network worth reaching"

(cd "$example" && docker compose up -d mysql >/dev/null 2>&1)

tell "A database on a compose network, with no published port. Try to reach it"
tell "from here and there is nothing to reach:"
cmd "docker run --rm alpine sh -c 'nc -z mysql 3306'   # nothing resolves it"
pause

say "5. now start the connector yourself"

tell "It is in the compose file but not running, because this is the part"
tell "worth watching. Start it, in another terminal or right here:"
cmd "cd $example && docker compose up -d vpn"
tell "It will enrol and wait. Nothing is granted by starting it."
pause

say "6. it is asking to be let in"

if ! waitfor "it to ask" 60 pending_arrived; then
  tell "Nothing arrived. Start it with the command above, or look at"
  tell "cd $example && docker compose logs vpn"
  exit 1
fi

./robinet member pending | sed 's/^/   /'

tell ""
tell "Everything there came from the connector and none of it is trusted: the"
tell "address is the hub's, the rest is what it said about itself. WILL BE"
tell "CALLED is the name it would answer under, and it is part of the decision."
tell ""
tell "Admit it, with the id from that table:"
cmd "./robinet member approve <id>"

if ! waitfor "you to admit it" 150 admitted; then
  tell "Still not admitted. ./robinet member pending shows what is waiting."
  exit 1
fi

say "7. what you can reach"

./robinet reach | sed 's/^/   /'

tell ""
tell "The name is <connector>.<instance>.robinet. Two networks calling"
tell "themselves the same thing stay apart, because the connector's name is"
tell "unique in the instance and the instance's is unique on the hub."
pause

say "8. reach it"

if [ "$example" = ipv6 ]; then
  tell "This network has no IPv4 at all, so ask for AAAA:"
  cmd "./robinet dns install    # a machine with systemd-resolved; this container has none"
  cmd "docker compose -f tenant/compose.yml exec tenant sh -c 'dig @198.19.0.2 -p 5354 AAAA mysql.warehouse.example.robinet +short'"
else
  cmd "./robinet dns install    # a machine with systemd-resolved; this container has none"
  cmd "docker compose -f tenant/compose.yml exec tenant sh -c 'dig @198.19.0.2 -p 5354 mysql.office.example.robinet +short'"
fi

tell "Then the port, which is the only real test - a connector answers pings"
tell "for every address it carries, including the empty ones:"
cmd "docker compose -f tenant/compose.yml exec tenant sh -c 'nc -z <that address> 3306 && echo reachable'"

say "done"
tell "./teardown.sh   removes all of it, keys included"
