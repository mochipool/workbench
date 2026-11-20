# Run a relay on Kubernetes

This page runs `spo-relay`, the relay mailbox of [ADR 0013](../explanation/adr/0013-tailnet-relay-and-mailbox.md) and [ADR 0014](../explanation/adr/0014-wallet-key-identity-for-the-relay.md), in a Kubernetes cluster. It is stage 6 of [ADR 0012](../explanation/adr/0012-server-backup-and-deployment.md), for the relay. The manifests are in [`deploy/kubernetes/relay/`](../../deploy/kubernetes/relay/). Read [Run a relay](./run-a-relay.md) first: the configuration and the key are the same.

> **Superseded: do not deploy this shape.** These manifests keep the relay's state on a volume in the pod. [ADR 0015](../explanation/adr/0015-stateless-relay.md) replaces them with pods that hold no state (an object store, a lease, a full DERP region in the configuration); its work package 13 rewrites the manifests and this page. A review also found open problems in this shape: the checks in `spo/test/deploy` can be passed by edits that remove a protection, the list of who can read the relay key is too short, the DNS and egress rules need work, and the backup advice below is wrong (an empty volume forgets every revoke). The page stays until then as a record of what was checked.
>
> **Not run on a cluster.** The manifests have never been applied, and the image has never been built. They are checked as files by `spo/test/deploy` (below). The Kubernetes facts they rely on are listed at the end; check them for your cluster.

## What the relay can and cannot see

The relay holds sealed envelopes until the device they are for fetches them. It cannot open them. It holds no wallet key, no workspace, no store and no signing key, and it signs nothing. It does not decide what an envelope asks.

It does see metadata: which devices and wallet keys talk to each other, when, and how much. Whoever runs the cluster sees the same, and can read the relay key from its Secret. With that key someone can pose as the relay: they can then drop or delay mail and see the same metadata, but still open nothing.

## What is not covered

* Block producers. They stay on systemd hosts ([ADR 0012](../explanation/adr/0012-server-backup-and-deployment.md), decision 11).
* The store, the workspace and the sealed layout. Nothing of them runs in the cluster.
* Any signing. No key that signs a transaction, a binding or a certificate is in the cluster.
* The server of ADR 0012 decisions 1, 5, 7 and 8 (ordering, object storage). It is not built.

## The layout

| Path | What |
| --- | --- |
| `base/shared/` | The namespace (it enforces the `restricted` Pod Security Standard), the service account (no token), the network policies and one disruption budget over all relays. Include it once. |
| `base/instance/` | One relay: a StatefulSet with one pod and its own claim, and the ConfigMap made from `relay.toml`. |
| `base/` | `shared` and one `instance`: a single relay. |
| `overlays/example/` | Two independent relays, `a` and `b`. Copy it for your own. |
| `Containerfile` | The image: a static `spo-relay` on a distroless base, user 10001. |

Plain manifests and kustomize only: no Helm, no custom resources, no operator.

## How the pod is put together

* **One pod per relay.** `replicas` stays 1. One key is one live tailcat endpoint, and each store directory is held by one process (a lock file). A second replica would serve the same key. For availability, run more relays, not more replicas.
* **The key comes from a Secret, through an init container.** `spo-relay` uses a key file only when it is a regular file of its own user with no group or other bit. A Secret volume's files belong to root, so the relay refuses them; this check is kept as it is. The init container (busybox, the same user 10001, no capability) runs:

  ```sh
  install -d -m 0700 /data/state /run/spo-relay/key
  install -m 0600 /secret/relay.key /run/spo-relay/key/relay.key
  ```

  It reads the Secret through its group: the Secret volume has mode 0440 and `fsGroup: 10001` makes 10001 its group. The copy goes to a memory `emptyDir`, never to the claim or the node's disk. Only the init container mounts the Secret; the relay container mounts the copy read-only. The trade-off: the key sits in the Kubernetes Secret store, so whoever can read Secrets in the namespace can read it. Turn on encryption of Secrets at rest, and give no one but the operator `get` on Secrets there.
* **The stores are on the pod's own claim**, under `/data/state`, a directory the init container makes with mode 0700. The relay refuses a store whose parent its group can write, and kubelet makes the claim's root group-writable (that is what `fsGroup` does). `fsGroupChangePolicy: OnRootMismatch` stops kubelet from changing every file at each start: a recursive change would add group bits to the stores' 0600 files and 0700 directories, and the stores refuse those.
* **The configuration** is a ConfigMap mounted as a directory (no `subPath`), with mode 0444 and owned by root. The relay accepts a file of root that nobody else can write. The ConfigMap's name has no hash suffix, so a change reaches the running pod in place.
* **Security context.** Non-root user and group 10001, read-only root file system, all capabilities dropped, no privilege escalation, `seccompProfile: RuntimeDefault`, no host namespaces, no service links, no service account token, no container port.
* **Network.** A default-deny policy for the namespace, and one for the relay that allows DNS to the cluster's DNS pods, and TCP 443 and UDP 3478 to public addresses (the DERP map, the DERP relays, STUN). Private, shared, link-local and loopback ranges are excluded, which keeps the cloud metadata address out of reach. There is no ingress rule: the relay opens no pod port, and its tunnel dials out. No direct peer-to-peer UDP path is allowed, so the traffic stays relayed through DERP. Your network plugin must enforce NetworkPolicy, or none of this applies.
* **No probes.** `spo-relay` has no health endpoint and writes no ready file. An HTTP or TCP probe would always fail. An exec probe of `spo-relay check-config` was considered and left out: it does not see the serving process, and it would kill a serving relay over a bad ConfigMap edit that the reload has already refused. The relay exits on a failure (status 3 when its tunnel did not stop), and kubelet restarts it. A real readiness check needs the binary to report that it is serving (for example a ready file and a `spo-relay` subcommand that reads it); that is not built.
* **Shutdown.** `terminationGracePeriodSeconds: 45`. The relay's teardown is bounded at 20 s (`relayhost.DefaultTeardown`); the rest is for closing the stores. There is no `preStop` hook.
* **Resources.** The relay requests 100m CPU and 128 MiB, with limits of 1 CPU and 512 MiB, and `GOMEMLIMIT=400MiB`. Each claim requests 10 GiB: the default global quota is 4 GiB of queues, plus the registry. Raise both if you raise `[quota] global_bytes`.
* **Disruption.** One budget, `maxUnavailable: 1`, over every relay of the namespace, so a drain takes at most one relay at a time. With one relay it still lets the drain go ahead, and the devices wait. A preferred anti-affinity spreads the relays over nodes.

## Steps

1. **Build the image.** Fill in the two digests in `Containerfile` (they are `sha256:FILL_IN_...` placeholders, which fail on purpose), then from the repository root:

   ```sh
   podman build -f deploy/kubernetes/relay/Containerfile -t REGISTRY/spo-relay:VERSION .
   ```

   With Nix: `tools/spo.nix` already builds the relay (`relay`, `subPackages = [ "cmd/spo-relay" ]`, `CGO_ENABLED = 0`). An image can be made from it with `pkgs.dockerTools.buildLayeredImage { name = "spo-relay"; config = { Entrypoint = [ "${relay}/bin/spo-relay" ]; User = "10001:10001"; }; }`. This is not in the flake and has not been built.

   Push the image, and write its digest into `base/instance/statefulset.yaml` (and the busybox digest for the init container). Leave no `FILL_IN_` in place.

2. **Make one key per relay, on a host.** Use a throwaway configuration with the same `[[device]]` tables, a private key directory and temporary store directories:

   ```sh
   umask 077
   mkdir -m 0700 key state
   # relay.toml: key_file = "$PWD/key/relay.key", mailbox_dir and registry_dir under $PWD/state
   spo-relay init-key --config relay.toml
   ```

   `init-key` prints the relay node key. Give it to every device's operator.

3. **Get the address once, on that host,** as in [Run a relay](./run-a-relay.md), step 5: `serve --print-address`, standard output to a private file, then stop it. Never put `--print-address` in a pod spec: the container log keeps what the pod prints, and the address holds the pre-shared key. Do it before the relay runs in the cluster: one key must not be live twice.

   **Open problem:** the address names the DERP region that the relay picked when it started. A relay that starts in the cluster may pick another region than your host did. Use a host near the cluster. Whether devices then reach the pod at that address is not confirmed (the handoff's manual row 37). A setting that pins the region would remove the doubt; it is not built.

4. **Store each key as a Secret,** one per relay, named as the overlay's patch says:

   ```sh
   kubectl -n spo-relay create secret generic spo-relay-key-a --from-file=relay.key=key/relay.key
   ```

   Keep a backup of the key file where you keep other secrets. A new key is a new address, and every device must be told. Then delete the host's copy and the temporary directories.

5. **Write the device lists** in `overlays/example/relay-a/relay.toml` and `relay-b/relay.toml`.

6. **Check, then apply.** From `spo/`, `go test ./test/deploy/` checks the manifests (run it in a container). Then apply with `kubectl apply -k deploy/kubernetes/relay/overlays/example`. The pod logs `spo-relay: serving` and the relay node key; compare it with step 2.

7. **Give each device the relays.** On each device: `spo party relay add a --node-key HEX --address-file FILE`, and again for `b`. A device lists at most 8 relays. It sends to all of them and fetches from all of them.

## Two or more relays

Each relay is its own instance: its own Secret, configuration, pod and claim. The relays share nothing but the namespace's objects, and they do not talk to each other. To add relay `c`, copy `overlays/example/relay-b` to `relay-c`, change `nameSuffix`, the `app.kubernetes.io/instance` label and the Secret name in `key-secret.yaml`, list it in the overlay, and make its key as in steps 2 to 4. Never give two instances one Secret or one claim; the checks refuse it.

For more availability than one cluster gives, run relays in different clusters or on hosts, and list them all on every device.

## Adding or removing a device

1. Edit the relay's `relay.toml` and apply the overlay. The ConfigMap changes in place.
2. Wait until kubelet has written the new file into the pod. That takes up to about a minute or two (its sync period and cache). Check with:

   ```sh
   kubectl -n spo-relay exec spo-relay-a-0 -c relay -- spo-relay check-config --config /etc/spo-relay/relay.toml
   ```

   It prints how many device node keys the file admits.
3. Send SIGHUP to the relay. The image has no shell or `kill`, so use an ephemeral debug container that shares the relay's process namespace and runs as the same user:

   ```sh
   echo '{"securityContext":{"runAsUser":10001,"runAsGroup":10001}}' > uid.json
   kubectl -n spo-relay debug spo-relay-a-0 --target=relay --profile=restricted --custom=uid.json \
     --image=docker.io/library/busybox:1.37@sha256:DIGEST -- kill -HUP 1
   ```

   The relay is process 1 in its container. Its log says `reloaded`, or why the reload was refused. Only the device list is reloaded; anything else needs a restart. The ephemeral container stays listed in the pod until the pod is replaced. This needs a runtime that supports a target container's process namespace, and `--custom` needs a recent `kubectl`.

   Or restart instead: `kubectl -n spo-relay rollout restart statefulset spo-relay-a`. The devices reconnect, and the other relays carry the mail meanwhile.

## Upgrades

Write the new image digest and apply. With one replica, the StatefulSet stops the old pod (SIGTERM, then up to 45 s) before it starts the new one, so the key is never live twice. The key, the address and the claim stay. Upgrade one relay at a time and wait for `serving` before the next.

## Backup of the volume and what losing it means

The claim holds the queues (sealed envelopes not yet fetched) and the binding registry (bindings and revoke tombstones). The key is not on it; it is in the Secret and in your backup from step 4.

* **Losing the queues** drops the mail that was waiting. The devices' outboxes send it again ([ADR 0013](../explanation/adr/0013-tailnet-relay-and-mailbox.md), "State and backup").
* **Losing the registry** forgets the bindings, so each device's next login presents its binding again. It also forgets the tombstones: until a revoke reaches the relay again, the relay accepts a revoked binding until that binding expires ([ADR 0014](../explanation/adr/0014-wallet-key-identity-for-the-relay.md), threat table). Devices send their pending revokes on every connection until the revoked binding ends, so the gap closes as they connect.
* **Restoring an older backup** is a full rollback: it brings back older bindings and forgets newer tombstones, and the relay cannot tell it from a restart (SPO-Xmailbox-SEC-063). The same client re-sending is the only defence.

So a backup of the claim gains little; an empty new claim is about as good. If you do back it up, use your storage's snapshots, and keep the snapshot's owner and modes: a restored volume whose root has another group makes kubelet change every file (the root no longer matches `fsGroupChangePolicy`), and the stores then refuse their own files. The fix is `chmod -R go-rwx /data/state` from a pod that runs as user 10001.

## The checks

`spo/test/deploy` reads every file of `deploy/kubernetes/relay/` (it skips when they are not there, as in the Nix build, which copies `spo/` only). It decodes the YAML with a strict decoder of the subset the manifests use, because a YAML library would change the module's vendored set and so the Nix `vendorHash`. It checks: the pod-security properties above, for every container; no Secret, no literal key, no cloud key and no `--print-address` anywhere; every image pinned by digest and no `latest`; each `relay.toml` passes the real `relayconfig.Parse` and `relayhost.Prepare`; the volumes laid out in a temporary directory as kubelet makes them pass the real `relayconfig.Load`, `relayconfig.LoadKey` and the two stores' `Open`; the grace period is at least the teardown bound plus 10 s; one replica, one claim per pod, the Secret only in the init container, no two instances with one Secret or one name; the default-deny and the relay's network policy; no probe; one disruption budget. `TestEveryCheckBites` breaks the manifests in 88 ways and requires each check to report its breakage.

## Kubernetes facts these manifests rely on

They are from memory, not from a cluster or the Kubernetes source. Check them:

1. Files of a Secret or ConfigMap volume belong to root. With `fsGroup` set, kubelet gives them the fsGroup as their group and adds group read (0440), not group write.
2. With `fsGroup` set, kubelet gives a claim's and an `emptyDir`'s root directory the fsGroup as group, group read, write and execute, and the setgid bit. An `emptyDir`'s root is world-writable.
3. `fsGroupChangePolicy: OnRootMismatch` skips the recursive change when the root's group and mode already match. It does not apply to Secret and ConfigMap volumes.
4. A ConfigMap volume mounted without `subPath` is updated in place (the `..data` link is swapped), within kubelet's sync period plus its cache delay. A `subPath` mount is never updated.
5. A StatefulSet with one replica and `RollingUpdate` deletes the old pod and waits until it is gone before it creates the new one.
6. Network policies are additive and stateful: replies to an allowed connection are allowed, a pod selected by a policy with type `Egress` and no rule has no egress, and `ipBlock` with `except` excludes those ranges.
7. Two disruption budgets that select one pod make every eviction of that pod fail.
8. Ephemeral containers made by `kubectl debug --target` share the target container's process namespace, and the restricted Pod Security Standard applies to them.
9. `ReadWriteOncePod` needs a CSI driver.
