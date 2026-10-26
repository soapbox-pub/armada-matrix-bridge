# Local test stack

A throwaway Synapse (server name `localhost`) and Postgres, both on host
networking so Synapse reaches the bridge on `127.0.0.1:8789`.

```sh
cp config.example.toml config.dev.toml       # then point it at the stack below:
#   homeserver.url = "http://127.0.0.1:8008", server_name = "localhost"
#   appservice.url = "http://127.0.0.1:8789"
#   database.url   = "postgres://armada:armada@127.0.0.1:5436/armada_matrix_bridge"
#   permissions    = { "localhost" = "bridge" }
cargo run -- -c config.dev.toml generate-registration && chmod 644 registration.yaml

docker run --rm -v "$PWD/dev/synapse:/data" -e SYNAPSE_SERVER_NAME=localhost \
  -e SYNAPSE_REPORT_STATS=no -e UID=$(id -u) -e GID=$(id -g) matrixdotorg/synapse generate
cat dev/homeserver.extra.yaml >> dev/synapse/homeserver.yaml
(cd dev && docker compose up -d)
docker compose -f dev/docker-compose.yml exec synapse \
  register_new_matrix_user -u tester -p testerpass -a -c /data/homeserver.yaml http://localhost:8008

cargo run -- -c config.dev.toml
```

## Driving it

`tools/armada-sim/sim.ts` is a small Armada client built on Armada's own
Concord library (it expects a checkout at `~/Projects/armada`; run it from that
directory so its imports resolve):

```sh
bun ../armada-matrix-bridge/tools/armada-sim/sim.ts create "Bridge Test"   # prints an invite link
bun ../armada-matrix-bridge/tools/armada-sim/sim.ts say general "hi" --as alice
bun ../armada-matrix-bridge/tools/armada-sim/sim.ts tail 20                 # decrypted chat
```

`dev/mx.py` is the Matrix side:

```sh
dev/mx.py login tester testerpass
dev/mx.py rooms
dev/mx.py send '!room:localhost' "hello" --reply '$event'
```

Invite `@armadabot:localhost` to a DM, send it `bridge <invite link>`, then
approve from Armada with `sim.ts say general "/bridge approve <code>"`.
