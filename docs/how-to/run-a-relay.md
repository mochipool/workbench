# Run a relay

A relay holds sealed signing envelopes for devices that are not online at the same time, and hands them out when the device logs in. It cannot open an envelope, holds no party secret, and decides nothing about what an envelope asks: the devices do ([ADR 0013](../explanation/adr/0013-tailnet-relay-and-mailbox.md), [ADR 0014](../explanation/adr/0014-wallet-key-identity-for-the-relay.md)).

Anyone can run a relay, and there can be several. Each relay is independent: its own key, address, store and device list. A device lists every relay it uses, sends to all of them and fetches from all of them, so one relay that is down or misbehaves does not stop the mail. Whoever runs a relay sees which devices and wallet keys talk to each other and when; run one per group of parties that trust you with that.

The configuration and the commands are listed in the [reference](../reference/relay-config.md).

> **Not run on a real network yet.** Everything here is tested in process over a fake tunnel. The checks that need a real network are rows 35 to 42 of the manual table in [the handoff](../development/handoff.md).

## On one host

1. Make a user and two private directories for the relay:

   ```sh
   sudo useradd --system --home /var/lib/spo-relay --create-home spo-relay
   sudo -u spo-relay mkdir -m 0700 /var/lib/spo-relay/key /var/lib/spo-relay/state
   ```

2. Ask each device's operator for its tailcat node key (`spo party show` prints it; the identity must be made with `spo party init --tailcat`). The relay's tunnel admits only the node keys you list.

3. Write `/var/lib/spo-relay/relay.toml`, owned by `spo-relay` and mode 0600:

   ```toml
   [relay]
   admission    = "open"
   key_file     = "/var/lib/spo-relay/key/relay.key"
   mailbox_dir  = "/var/lib/spo-relay/state/mailbox"
   registry_dir = "/var/lib/spo-relay/state/registry"

   [[device]]
   label    = "alice laptop"
   node_key = "<alice's node key, 64 hex digits>"

   [[device]]
   label    = "bob server"
   node_key = "<bob's node key>"
   ```

   Pin the DERP region in full, so that the address you hand out stays the same across restarts. The address embeds the region's nodes, so copy them from the DERP map you use (or from your own DERP server) into the file:

   ```toml
   [derp_region]
   region_id = 900

   [[derp_node]]
   name      = "own-1"
   host_name = "derp.example.org"
   # cert_name = "sha256-raw:<64 hex digits>"   # for a self-signed certificate
   ```

   Without it the relay picks the nearest region at every start, logs `derp_region=unpinned`, and its address may change. `derp_region_id = N` in `[relay]` fixes the region but not the address, which then follows the public map, and it does not pin the DERP server: the map's operator chooses it. If you later edit a node, the address changes and every device needs the new one. See [the reference](../reference/relay-config.md#the-derp-region-derp_region-and-derp_node).

   At start the relay connects to the pinned region over verified TLS and completes a DERP handshake. If `cert_name` (or its hash) is wrong, or the DERP port is down, `serve` stops with status 1 and says which; fix the node and start again. The DERP server's operator can see who connects and when, and can test whether a node key is listed, but cannot read the tunnel: pick a DERP server you trust with that metadata.

   Do not set any `TS_DEBUG_*` variable in the relay's environment (unit file, container, shell). The relay refuses to start with one set: `TS_DEBUG_ADDR` would print the address, with its pre-shared key, to the log.

   `admission = "open"` lets any listed device log in with a valid binding. To accept only some wallet keys as well, write `admission = "allow-list"` and add a `[[wallet]]` table (`label`, `key` of 56 hex digits) for each.

4. Check it, then create the key once:

   ```sh
   sudo -u spo-relay spo-relay check-config --config /var/lib/spo-relay/relay.toml
   sudo -u spo-relay spo-relay init-key --config /var/lib/spo-relay/relay.toml
   ```

   `init-key` prints the relay node key. Back up `relay.key` with the configuration; a new key is a new address that every device must be told.

5. Get the address once, by hand, and give each device's operator the node key and the address by a channel you trust. The address holds the pre-shared key: anyone who has it can reach the relay's tunnel.

   **Never put `--print-address` in a unit file, a supervisor's command, a container's command or a pod spec.** Whatever the supervised process writes goes to the journal or the container log, and the address would stay there. Run it once from a shell, with the supervised relay stopped (one key is one live endpoint), standard output going to a file only you can read:

   ```sh
   sudo -u spo-relay sh -c 'umask 077 && spo-relay serve --config /var/lib/spo-relay/relay.toml --print-address > /var/lib/spo-relay/address.once'
   # wait for "serving" (on standard error the warning about the secret), then Ctrl-C
   sudo -u spo-relay sed -n 's/^address //p' /var/lib/spo-relay/address.once
   sudo -u spo-relay rm /var/lib/spo-relay/address.once
   ```

   Each operator writes the address to a file that only they can read (`umask 077`, or `chmod 600`; `spo party relay add` refuses a file that its group or others can read or write), stores it with `spo party relay add NAME --node-key HEX --address-file FILE`, deletes the file, and compares the node key with you out of band. Do it again only when the key or the `[derp_region]` tables change, or a device reports that the address no longer reaches the relay.

6. Run it under a supervisor that restarts it, without `--print-address`. It exits with status 3 when its tunnel did not stop, also when that happens in a start that failed; a restart is the recovery. Status 4 means it is no longer the writer of its store (a lost lease; with directory stores this does not happen); a restart is the recovery there too. It opens no inbound TCP port; the tunnel engine binds two UDP sockets on system-chosen ports and needs outbound access to the DERP relays.

### Adding or removing a device

Edit the `[[device]]` tables and send SIGHUP. Only the device list is reloaded; a file that differs in anything else is refused and the list in force stays. Removing a device rebuilds the tunnel (same address) and ends that device's connections, and the relay ends its logged-in sessions itself (`close reason=delisted` in the log); the others reconnect.

Changing anything else (admission, wallet keys, limits, quotas, retention, paths, port) takes a restart. The registry and the queue survive a restart.

## On Kubernetes

See [Run a relay on Kubernetes](./run-a-relay-on-kubernetes.md) and the manifests in [`deploy/kubernetes/relay/`](../../deploy/kubernetes/relay/) (not applied to a cluster yet). In short: one relay is one StatefulSet with one replica, its own key Secret, configuration and claim; more relays are more instances, never more replicas; an init container copies the key into a memory volume with mode 0600, because a Secret's files belong to root; the address is got once on a host, never printed in the cluster. Not confirmed: DERP reachability from a pod network, and that a restarted pod with the same key resumes service. Pin the region in full (`[derp_region]`): then the address made on a host is the address the pod has, by construction; without the pin the pod picks its own region and the address may differ.
