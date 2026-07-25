# prx wire protocol v1

This is the reference for anyone writing a second implementation — the
Android client is the next one. It describes what goes on the wire and,
where it matters, why.

All integers are big-endian. "Key" means the 32-byte pre-shared key carried
in a `prx://` link.

## 1. Transport

A connection is an ordinary TLS session on TCP. The client sends a ClientHello
copied from a real browser (uTLS), including the SNI the user chose. The
server answers with a certificate for that name.

The client does **not** validate the certificate. In the default server mode
there is nothing to validate against: the certificate is self-signed and
minted on demand to match whatever SNI arrived. Authentication happens in
stage 2 instead, and is strictly stronger than name validation here — see §2.

TLS 1.2 is accepted, TLS 1.3 is what real clients negotiate. The only
requirement is that RFC 5705 key export be available, which means TLS 1.3 or
TLS 1.2 with extended master secret.

ALPN: the server offers `h2, http/1.1` when using the built-in decoy and
`http/1.1` when a fallback web server is configured, because that fallback is
reached over cleartext HTTP/1.1.

## 2. Authentication

Both sides derive a channel binding from the completed handshake:

```
binding = TLS-Exporter("EXPORTER-prx-auth-v1", context = empty, length = 32)
```

The client sends, as its first bytes:

| field   | size | contents                                        |
|---------|------|-------------------------------------------------|
| nonce   | 16   | random                                          |
| tag     | 32   | `HMAC-SHA256(key, "prx-client-v1" ‖ binding ‖ nonce)` |
| padlen  | 2    | 0 … 900                                         |
| padding | *n*  | random                                          |

The server replies:

| field   | size | contents                                        |
|---------|------|-------------------------------------------------|
| tag     | 32   | `HMAC-SHA256(key, "prx-server-v1" ‖ binding ‖ nonce)` |
| padlen  | 2    | 0 … 900                                         |
| padding | *n*  | random                                          |

No user identifier appears on the wire. The server finds the key by computing
the expected tag for each enabled user and comparing in constant time — one
HMAC per user per connection.

### What the binding buys

- **Machine-in-the-middle.** An attacker who terminates TLS derives binding
  `B1` with the client and `B2` with the server. The client's tag covers `B1`,
  so forwarding it fails the server's check against `B2`; forging the server's
  tag needs the key. Both sides abort. This holds even though the client never
  validated a certificate, and even if the attacker holds a valid certificate
  for the SNI.
- **Replay.** Every TLS session produces a fresh binding, so a recorded tag
  never validates again. No nonce database and no clock synchronisation.
- **Active probing.** Anyone without the key gets §5.

### Client behaviour

The client must not treat the connection as usable until the server's tag
verifies. Failing that check is indistinguishable from "this is not a prx
server", because that is exactly what a probing client sees.

## 3. Request

Sent by the client once authenticated. On a pooled connection this is
deferred until there is something to send, which is what removes the
handshake from the critical path.

| field   | size | contents                       |
|---------|------|--------------------------------|
| cmd     | 1    | `0x01` TCP connect, `0x02` UDP associate |
| address | var  | present for `0x01` only, see §4 |
| padlen  | 2    | 0 … 900                        |
| padding | *n*  | random                         |

**There is no reply.** The client may send payload immediately after the
header, and a destination that cannot be reached is reported by the server
closing the connection. This is deliberate: a status round trip would add one
full RTT to every request, which on a 150 ms link is 150 ms of latency for
information the client learns anyway.

After the header the connection is a raw bidirectional relay.

## 4. Address encoding

Identical to SOCKS5, so addresses pass between the two without translation.

| field | size | contents                                          |
|-------|------|---------------------------------------------------|
| type  | 1    | `0x01` IPv4, `0x03` domain, `0x04` IPv6           |
| host  | var  | 4 bytes / length-prefixed name (1 + n) / 16 bytes |
| port  | 2    |                                                   |

A domain name is at most 255 bytes and must not be empty.

## 5. Unauthenticated connections

Anything that fails §2 is served as an ordinary web visitor: either relayed
to the configured fallback web server, or answered by the built-in decoy page
over whichever HTTP version ALPN selected.

Two details matter for this to be believable:

- The server recognises an HTTP request by its first four bytes (`GET `,
  `POST`, `PRI ` and so on) *before* waiting for a full 48-byte
  authentication record. Otherwise a complete-but-short request such as
  `GET / HTTP/1.0` would hang until the handshake timeout while a real web
  server answered at once — a difference a scanner can measure. A genuine
  client, whose record begins with 16 random bytes, collides with this check
  about once in four billion connections and simply reconnects.
- Bytes already read while making the decision are replayed to the decoy, so
  the visitor's request is not truncated.

## 6. UDP

After `cmd = 0x02` the stream carries datagrams in both directions:

| field   | size | contents                                    |
|---------|------|---------------------------------------------|
| length  | 2    | bytes that follow, address included         |
| address | var  | §4 — destination outbound, source inbound   |
| payload | var  |                                             |

One unconnected UDP socket on the server serves the whole association, so
every destination sees the same source port and replies return where they are
expected. The server remembers which name each destination was reached under
and reports replies under that name, because an application that sent to
`dns.example` may discard a packet that appears to come from an IP address.

The association ends when the stream closes, or after two minutes with no
traffic in either direction.

## 7. Link format

```
prx://<key>@<host>:<port>?sni=<name>&fp=<fingerprint>#<label>
```

- `key` — base64url, no padding, 32 bytes decoded
- `sni` — TLS server name; free to choose, defaults to `www.cloudflare.com`
- `fp` — ClientHello to imitate: `chrome` (default), `firefox`, `safari`,
  `ios`, `edge`, `android`, `random`
- `label` — display name

Defaults are omitted when the link is generated, so a minimal link is just
`prx://<key>@<host>:<port>`.

## 8. Reserved for later

`cmd` values `0x03`–`0xff` are unassigned. Stream multiplexing, when it
arrives for mobile battery life, will be negotiated as a new command rather
than by changing any structure above.
