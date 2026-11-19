# Upstream reports for tailcat: drafts

**These are drafts. None has been sent, filed or shared anywhere.** They describe behaviour of `github.com/tailscale/tailcat` v0.7.0 and `tailscale.com` as read in source and reproduced in process. Line numbers refer to those versions. Check each against the current upstream before filing. They contain no detail of this project.

## U1. A client accepts a forged "meowed" acknowledgment

**Description.** `Client.initLocked` installs a DERP receive hook (`lb.onDERPRecv`, tailcat.go around lines 1935 to 1941). For any packet for which `IsMeowedPacket(pkt)` holds it runs `onMeowed`, which closes `meowWait` and treats the client as registered with the server. The hook never looks at the sender (`src`). Any DERP client that knows a victim client's public node key and the DERP region can send an `EncodeMeowed()` packet to it. The victim then believes the server registered it, `upDone` stays true (`Client.up` never registers again), and every `DialTCPPort` times out, because the server never added the client as a peer.

The same wedge happens without an attacker when the server restarts between the acknowledgment and the first successful dial, and, more generally, whenever a client that registered once talks to a server that has lost its client table: registration happens once and is never repeated.

**Minimal reproduction.**

1. Run a DERP server and a tailcat `Server` with an allow-list that names client A.
2. Start client A (a `tailcat.Client` for that server) in the same process or another.
3. From a third DERP client that knows A's public node key and the region, send `EncodeMeowed()` to A every 20 ms.
4. Keep the server down while this runs, then start it with the same keys.
5. `A.DialTCPPort` never succeeds; without the forged packets and with the server started before A's first dial it succeeds at once.

**Suggested fix.**

* In `onDERPRecv`, accept a meowed packet only when `src` is the server's public key (`lb.serverPub`).
* Re-run the registration handshake (`upDone.Store(false)`) when a dial through an up client fails by timeout, or after a WireGuard handshake failure towards the server, so that a restarted server is found again.

Until then a caller can only work around it by discarding the client and building a new one after a failed dial.

## U2. `Server.Close` and `Client.Close` never return with about 512 or more TCP endpoints

**Description.** `wgengine/netstack.Impl.Close` (netstack.go around lines 445 to 454) first cancels the injection goroutines (`ns.ctxCancel()`) and then calls `ipstack.Close()`. gVisor's `Stack.Close` (stack.go around lines 2064 to 2067) aborts every registered endpoint, and each abort writes a reset into the link endpoint's outbound queue. That queue has 512 slots (`newLinkEndpoint(512, ...)`, netstack.go around line 408) and nothing drains it any more, because the goroutines that did were just cancelled. When the stack holds more endpoints than the queue has slots, the write blocks and `Close` never returns. The engine, its UDP sockets and its DERP connection stay up for the life of the process.

**Minimal reproduction.**

1. A tailcat `Server` with a TCP listener on one port (accepting nothing, or accepting and holding).
2. 600 clients, or 600 connections from one client, dialled and held open.
3. Call `Server.Close()`. It does not return; the same happens with `Client.Close()` on the dialling side.

**Suggested fix.** Drain or discard the outbound queue while closing: cancel the injection goroutines only after `ipstack.Close()` has returned, or make the queue write non-blocking once closing has started. Document that `Close` aborts connections. Until it is fixed, callers must keep the endpoint count well below 512 and bound their wait for `Close`.

## U3. With an empty allow-list anyone who knows the server's key and region can register, and registrations are permanent

**Description.** The registration ("meow") ping carries only the sender's node key and disco key (`EncodeMeowPing`, `ParseMeowPing`, disco.go around lines 30 to 65). `onMeow` (tailcat.go around lines 1670 to 1730) checks only the allow-list (`b.allowedClients != nil && !b.allowedClients[src]`), never the pre-shared key; the pre-shared key is applied later, in `peerConfig`, for the WireGuard handshake. When the allow-list is empty, `allowedClients` is nil and every sender is admitted.

Each admitted registration is permanent: `onMeow` adds the client to `b.clients`, nothing in tailcat.go ever deletes from it, and `AddAllowedClient` only inserts. Each registration also costs work that grows with the number of clients:

* the whole network map is rebuilt and sorted (around lines 1710 to 1716), then `SetNetworkMap` and `UpdateNetstackIPs` run (around lines 1722 to 1725);
* `go b.advertiseEndpoints()` starts for every registration (around line 1730) and sends a sealed CallMeMaybe to every peer (around lines 1521 to 1556); N registrations send N(N+1)/2 messages;
* `peerByIP` scans `b.clients` linearly, under the lock, for every outbound packet (around lines 1458 to 1462), because it is installed as the engine's `SetPeerByIPPacketFunc` (around line 1642) and WireGuard calls it instead of its allowed-IPs trie.

A server in this mode therefore degrades without bound under registrations from anyone who knows its public key and DERP region.

**Minimal reproduction.**

1. A `Server` with no `AllowedClients`.
2. From many fresh node keys, send a registration ping through the DERP region, without the pre-shared key.
3. Observe `len(b.clients)` grow, never shrink, and the time of each registration and of each outbound packet grow with it.

**Suggested fix.** Make registration require proof of the pre-shared key (for example a MAC of the registration ping under the key), so that a stranger cannot add clients. Let the server drop clients (`delete(b.clients, k)` with a network-map update), bound their number, and replace the linear `peerByIP` scan by an indexed lookup.
