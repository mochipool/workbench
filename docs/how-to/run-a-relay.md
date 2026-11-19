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

   Each operator writes the address to a file that only they can read (`umask 077`, or `chmod 600`; `spo party relay add` refuses a file that its group or others can read or write), stores it with `spo party relay add NAME --node-key HEX --address-file FILE`, deletes the file, and compares the node key with you out of band. Do it again only when the key changes or a device reports that the address no longer reaches the relay.

6. Run it under a supervisor that restarts it, without `--print-address`. It exits with status 3 when its tunnel did not stop, also when that happens in a start that failed; a restart is the recovery. It opens no inbound TCP port; the tunnel engine binds two UDP sockets on system-chosen ports and needs outbound access to the DERP relays.

### Adding or removing a device

Edit the `[[device]]` tables and send SIGHUP. Only the device list is reloaded; a file that differs in anything else is refused and the list in force stays. Removing a device rebuilds the tunnel (same address) and ends that device's connections, and the relay ends its logged-in sessions itself (`close reason=delisted` in the log); the others reconnect.

Changing anything else (admission, wallet keys, limits, quotas, retention, paths, port) takes a restart. The registry and the queue survive a restart.

## On Kubernetes (outline)

Not built yet; manifests are a later stage. The shape:

* **One relay is one workload with `replicas: 1`, its own key and its own volume.** One tailcat node key is one live endpoint, and each store has one owner (a lock file). For availability, run several independent relays (several workloads, each with its own key Secret, configuration and volume) and list all of them on every device. Never scale one workload past one replica, and never share a key or a volume between two. There is no clustering and no shared state.
* `strategy: Recreate`, so the old pod has stopped before the new one starts with the same key.
* **Run as a non-root user.** Pod and container security context: `runAsNonRoot: true`, a fixed `runAsUser` and `runAsGroup` (for example 10001), `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities: {drop: [ALL]}`, `seccompProfile: {type: RuntimeDefault}`. The relay needs no capability and writes only to its volume.
* **The key file is copied by an init container.** The relay uses a key file only if it is a regular file owned by the relay's own user with no group or other permission bit; a Secret volume's files belong to root. Mount the Secret only in an init container that runs as the same non-root user and copies the key into a directory on the relay's volume: `install -d -m 0700 /data/key /data/state && install -m 0600 /secret/relay.key /data/key/relay.key`. Do not mount the Secret in the relay's container, and point `key_file` at `/data/key/relay.key`. The directory that holds the key must not be writable by its group or others, so use a directory the init container made, not the root of an `emptyDir` (which is world-writable).
* The configuration as a ConfigMap, mounted read-only (its files belong to root and are not writable by others, which the relay accepts). `mailbox_dir` and `registry_dir` under `/data/state` on the persistent volume.
* **The address is never printed in the cluster.** `--print-address` in the container's command would put the pre-shared key in the container log. Get the address once on a host, as in step 5 above, from the same key file, with the workload scaled to 0 while you do it.
* No Service and no inbound exposure; an egress policy that allows the DERP relays (and the DERP map address).
* A reload is SIGHUP to the process; a new ConfigMap needs it, or a restart.
* Not confirmed: DERP reachability from a pod network, and that a restarted pod with the same key resumes service.
