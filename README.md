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

## Parity

prism-parity's `human-plus-tool-admission` corpus compares tool admission with
the PHP reference and the TypeScript port. Admission and the confirmation-tool
reservation agree on every case.

Two pins differ. A tool with no schema gets a different digest in the PHP
reference, and a schema containing an integral float such as `1.0` gets a
different digest here. Compute a pin in the language that checks it.

## License

MIT. See [LICENSE](LICENSE).
