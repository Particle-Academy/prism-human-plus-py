# Prism Human+ for Python

Humans and agents sharing one application surface, across a trust boundary. The
Python port of [`particle-academy/prism-human-plus`](https://github.com/Particle-Academy/prism-human-plus).

Zero runtime dependencies. Python 3.10+.

```
pip install prism-ai-human-plus
```

An agent joins a running application surface, such as a spreadsheet a person
has open, through the invitation that surface issued. It sees the surface's
tools, calls the ones it is trusted with, and announces what it is doing to the
people watching.

```python
from prism_human_plus import (
    HumanPlusManager,
    HumanPlusToolset,
    InMemoryAttachmentStore,
    Participant,
    SsePostRelayTransport,
    SurfaceInvitation,
    TrustPolicy,
)

transport = SsePostRelayTransport(
    my_http,
    allowed_relay_hosts=["relay.example.com"],
    egress_proxy="http://egress-proxy.internal:3128",
)

human_plus = HumanPlusManager(
    transport,
    InMemoryAttachmentStore(),
    TrustPolicy.allowing(["sheet_read", "sheet_propose_edit"]),
)

attachment = human_plus.attach(
    session,
    SurfaceInvitation(
        relay_base_url="https://relay.example.com",
        session_id=invitation["session_id"],
        token=invitation["token"],
        surface_id=invitation["surface_id"],
        application="sheets",
    ),
    Participant(id="agent-1", name="Assistant", color="#7c3aed"),
)

tools = HumanPlusToolset(human_plus).for_attachment(
    session, attachment.id, approval_tools=["sheet_propose_edit"]
)
```

`my_http` is your HTTP client, behind the `RelayHttp` protocol (`post` and
`stream`). `session` is the owner: a string, or anything with a `key()` method,
such as a `prism-ai-harness` session.

## Trust

`TrustPolicy` decides which of the surface's tools the agent may see and call.

- **`TrustPolicy.undeclared()`** refuses discovery itself: no request of any
  kind reaches the surface, so no tool description reaches the model.
- **`TrustPolicy.allowing([...])`** allows the named tools.
- **`TrustPolicy.every_tool()`** allows every tool the surface offers.
- **Pins.** Pass `pins={name: digest}` to any of them. A pin is
  `ToolDefinition.digest()`, a fingerprint of the tool's name, description and
  schema. A tool whose definition no longer matches its pin is refused.
- **Confirmation tools belong to the human.** A tool named `confirm`, `reject`,
  `accept`, `approve` or `deny`, or ending in `_confirm`, `_reject` and so on, is
  refused under every policy, including `every_tool()`. The name is normalised
  first, so a trailing space or an invisible character does not get around it.
- A malformed tool name is refused.

Every refusal raises `ToolRefused`.

**Approval is your decision, not the surface's.** `HumanPlusToolset` marks a
tool `requires_approval` only if you list it in `approval_tools`. The surface's
own annotations are not consulted.

## Results

Every tool result passes through a `ResultGuard`:

- A result over the byte budget (65,536 by default) is refused, not truncated.
- The text is wrapped in an `<untrusted-tool-output>` tag with a random id, so
  the surface's output cannot close the wrapper.

The wrapper makes a prompt injection harder. It does not make one impossible.

## Attachments

- An attachment id locates state; it is not a credential. Every call re-presents
  the owner, and an attachment belonging to another owner raises
  `AttachmentUnauthorized`.
- `SurfaceInvitation` is validated when built: an HTTPS relay URL, a
  well-formed session id and a token of at least 16 characters.
- A surface that has gone (`410 session_gone`) raises `SurfaceUnavailable`. One
  that was never authorized (`401`) raises `AttachmentUnauthorized`. Each is
  recorded as its own terminal state, and neither is retried.
- `AttachmentStore` writes carry a generation, so two workers cannot overwrite
  each other's state. `InMemoryAttachmentStore` is for tests and single
  processes.

Every failure subclasses `HumanPlusError`.

## The relay transport

`SsePostRelayTransport` speaks the Fancy relay: a POST, then a bounded
server-sent-events stream.

- The relay URL is checked on every call against `allowed_relay_hosts` and
  `allowed_relay_ports` (443 by default). A literal private address is refused.
- It refuses to run without an `egress_proxy` unless you pass
  `allow_unverified_egress=True`, which is for isolated local testing only.
- Declaring `egress_proxy` does not route traffic by itself. Your `RelayHttp`
  must send its requests through it. Host names are not resolved here, so the
  proxy is what stops a public name that resolves to a private address.
- A frame over `max_frame_bytes` (262,144 by default) is refused.

## Two writers, and what changed since my last turn

**A human editing the same surface as the agent used to lose their work in
silence.** The agent read, the person committed, the agent wrote, and both
writes succeeded — which is exactly what a lost update looks like from the
inside.

Two mechanisms, and they answer different questions.

### The revision: did the world move under me

A tool result may carry a marker for the state it just showed. It is stored on
the attachment and **pinned to every later call** — reads included, because this
package cannot tell a read from a write and MCP's `readOnlyHint` is explicitly a
hint the spec says not to trust for security decisions.

If the surface says the marker is stale the call is refused with
`SurfaceChangedUnderYou`, **nothing is written**, and the stored marker is
dropped so the agent can read again.

`conflict_detection()` reports what has been OBSERVED, which is less than what
is configured:

| `ConflictDetection` | What is known |
|---|---|
| `NOT_OBSERVED` | The surface has not answered yet. |
| `UNAVAILABLE` | It mints nothing. A concurrent edit **will** be lost silently. |
| `MINTED` | It mints, so every call is pinned. Whether it **enforces** is not observable. |
| `ENFORCED` | It refused a stale pin. Proven, because it happened. |

`MINTED` is the one to read carefully. The reference's first integrator minted
on every write result and read an incoming pin nowhere, so a pinned call was
applied exactly as an unpinned one — and the boolean this replaced said `True`.

### The change feed: what did somebody else do

A revision stops an agent overwriting a change it did not know about. It does
nothing about an agent that re-reads, sees current state, decides the surface
has drifted from what it intended, and puts it back — over a person's edit, with
nothing stale anywhere and no error at any layer.

```python
changes = human_plus.changes_since(owner, attachment_id)

if not changes.answered():
    ...  # the surface has no feed; an empty list is NOT evidence of quiet

for change in changes.defer_to():
    change.handle  # the surface's own id
    change.kind  # CREATED | UPDATED | DELETED | MOVED | UNKNOWN
    change.actor  # HUMAN | AGENT | OTHER | UNKNOWN
```

**The empty list is the dangerous value.** "Nothing changed since your marker"
and "I cannot answer that question" are the same empty list on the wire, so
`ChangeFeed` comes first and `nothing_changed()` is the only method that means
what an empty list looks like it means.

**Attribution is the load-bearing field.** A change is deferred to unless the
surface positively said this agent made it. On a surface where every write path
is an agent tool — the first one asked is exactly that — nothing is attributed,
so everything is deferred to: not because it is all a person's, but because none
of it can be shown to be the agent's own.

`complete` is true unless the surface says otherwise. It exists because feeds
have holes their authors know about: the first surface asked hard-deletes rows
with no tombstone, so a removal moves no revision and appears in no feed.

See the reference's README for the surface's half of the contract — the tool
names, the key names read per field, and why `change` must be sent even when
`kind` is.

## Parity

prism-parity's `human-plus-tool-admission` corpus compares tool admission with
the PHP reference and the TypeScript port. Admission and the confirmation-tool
reservation agree on every case.

Two pins differ. A tool with no schema gets a different digest in the PHP
reference, and a schema containing an integral float such as `1.0` gets a
different digest here. Compute a pin in the language that checks it.

## License

MIT. See [LICENSE](LICENSE).
