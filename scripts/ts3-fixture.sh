#!/usr/bin/env bash
# Provision the local TS3 test server so the integration suite exercises real
# behaviour instead of skipping on permissions.
#
#   docker run -d --name ts3 -e TS3SERVER_LICENSE=accept \
#     -p 9987:9987/udp -p 10011:10011 -p 30033:30033 teamspeak:latest
#   ./scripts/ts3-fixture.sh
#   source ts3-fixture.env
#   go test -tags integration ./...
#
# Creates the channels the tests need (one password-protected), grants the
# default server group the permissions they exercise, relaxes anti-flood so a
# handful of rapid connections from one IP are not banned, and writes
# ts3-fixture.env with the matching environment variables.
set -euo pipefail

CONTAINER="${TS3_CONTAINER:-ts3}"
QUERY_HOST="${TS3_QUERY_HOST:-}"
QUERY_PORT="${TS3_QUERY_PORT:-10011}"
ADMIN_PW="${TS3_ADMIN_PW:-$(docker logs "$CONTAINER" 2>&1 | grep -o 'password= "[^"]*"' | head -1 | cut -d'"' -f2 || true)}"
# WebQuery needs its own key. TS3 prints one next to the admin password; TS6
# prints an apikey line of its own.
HTTP_API_KEY="${TS3_API_KEY:-$(docker logs "$CONTAINER" 2>&1 | grep -o 'apikey= "[^"]*"' | head -1 | cut -d'"' -f2 || true)}"
PASSWORD_CHANNEL="${TS3_PASSWORD_CHANNEL:-Secret}"
PASSWORD_CHANNEL_PASSWORD="${TS3_PASSWORD_CHANNEL_PASSWORD:-hunter2}"
DEFAULT_CHANNEL="${TS3_DEFAULT_CHANNEL:-Alpha}"

if [ -z "$ADMIN_PW" ]; then
  echo "could not read the serveradmin password from 'docker logs $CONTAINER'" >&2
  exit 1
fi

# Send ServerQuery commands.
#
# Three transports, because the two server generations disagree about this:
#
#   TS3  raw ServerQuery on TCP 10011 (nc inside the container, or over the
#        network in CI)
#   TS6  no raw query at all — it serves HTTP instead, so the same commands go
#        over WebQuery, which TS3 also supports
#
# The commands themselves are identical either way, so this stays one fixture
# rather than one per server generation. Set TS3_QUERY_HTTP to use WebQuery;
# otherwise TS3_QUERY_HOST picks direct TCP, and failing both it runs nc inside
# the container.
# Translate one raw ServerQuery line into a WebQuery request.
#
# The commands are identical; only the framing differs. "serveredit a=1 b=2"
# becomes GET /1/serveredit?a=1&b=2, and a bare "servergrouplist" becomes
# /1/servergrouplist.
query_http_line() {
  local line="$1"
  local name rest
  name="${line%% *}"
  if [ "$name" = "$line" ]; then
    curl -sS --max-time 10 -H "x-api-key: $HTTP_API_KEY" \
      "http://${TS3_QUERY_HTTP}/1/${name}" 2>/dev/null || true
    return
  fi

  rest="${line#* }"
  # Parameters are space-separated key=value pairs; URL-encode the separators.
  local query
  query="$(printf '%s' "$rest" | sed 's/ /\&/g')"
  curl -sS --max-time 10 -H "x-api-key: $HTTP_API_KEY" \
    "http://${TS3_QUERY_HTTP}/1/${name}?${query}" 2>/dev/null || true
}

query() {
  if [ -n "${TS3_QUERY_HTTP:-}" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      # login/use address the raw query session, which WebQuery replaces with
      # the API key; sending them would just be two unknown commands.
      case "$line" in
        login* | use*) continue ;;
      esac
      query_http_line "$line"
    done
    return
  fi

  if [ -n "$QUERY_HOST" ]; then
    {
      printf 'login serveradmin %s\r\nuse 1\r\n' "$ADMIN_PW"
      while IFS= read -r line; do printf '%s\r\n' "$line"; done
      printf 'quit\r\n'
      sleep 2
    } | nc -w 4 "$QUERY_HOST" "$QUERY_PORT"
    return
  fi

  {
    printf 'login serveradmin %s\r\nuse 1\r\n' "$ADMIN_PW"
    while IFS= read -r line; do printf '%s\r\n' "$line"; done
    printf 'quit\r\n'
    sleep 2
  } | docker exec -i "$CONTAINER" nc -w 4 127.0.0.1 "$QUERY_PORT"
}

# Grant to the group new clients actually join, which is whatever the server
# reports as its default — hard-coding a group id is how the tests end up
# skipping on permissions. 'channel name is already in use' on a re-run is
# harmless.
DEFAULT_GROUP="$(query <<'PROBE' | grep -o 'virtualserver_default_server_group=[0-9]*' | head -1 | cut -d= -f2 || true
serverinfo
PROBE
)"
DEFAULT_GROUP="${DEFAULT_GROUP:-8}"

query <<COMMANDS
serveredit virtualserver_antiflood_points_needed_command_block=65000 virtualserver_antiflood_points_needed_ip_block=65000 virtualserver_antiflood_points_tick_reduce=65000
channelcreate channel_name=$DEFAULT_CHANNEL channel_flag_permanent=1
channelcreate channel_name=$PASSWORD_CHANNEL channel_flag_permanent=1 channel_password=$PASSWORD_CHANNEL_PASSWORD
servergroupaddperm sgid=$DEFAULT_GROUP permsid=b_virtualserver_channel_list permvalue=1 permnegated=0 permskip=0
servergroupaddperm sgid=$DEFAULT_GROUP permsid=b_virtualserver_client_list permvalue=1 permnegated=0 permskip=0
servergroupaddperm sgid=$DEFAULT_GROUP permsid=b_virtualserver_info_view permvalue=1 permnegated=0 permskip=0
servergroupaddperm sgid=$DEFAULT_GROUP permsid=b_client_info_view permvalue=1 permnegated=0 permskip=0
servergroupaddperm sgid=$DEFAULT_GROUP permsid=b_client_remoteaddress_view permvalue=1 permnegated=0 permskip=0
servergroupaddperm sgid=$DEFAULT_GROUP permsid=i_client_whisper_power permvalue=100 permnegated=0 permskip=0
COMMANDS

# The voice port is configurable because a second server on the same host needs
# a different one; CI maps the first to 9987 either way.
VOICE_PORT="${TS3_VOICE_PORT:-9987}"

cat > ts3-fixture.env <<ENVFILE
# Generated by scripts/ts3-fixture.sh — source before running the integration suite.
export TEAMSPEAK_ADDR=127.0.0.1:$VOICE_PORT
export TEAMSPEAK_DEFAULT_CHANNEL=$DEFAULT_CHANNEL
export TEAMSPEAK_PASSWORD_CHANNEL=$PASSWORD_CHANNEL
export TEAMSPEAK_PASSWORD_CHANNEL_PASSWORD=$PASSWORD_CHANNEL_PASSWORD
ENVFILE

echo "fixture ready — run: source ts3-fixture.env && go test -tags integration ./..."
