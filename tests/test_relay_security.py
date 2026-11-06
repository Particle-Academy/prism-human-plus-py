from __future__ import annotations

import json
import socket
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import prism_human_plus as human

FIXTURE = json.loads((Path(__file__).parent / "fixtures/relay-security.json").read_text())
FRAME: human.JsonObject = {"jsonrpc": "2.0", "id": "probe", "method": "tools/call", "params": {}}
RPC = 'data: {"jsonrpc":"2.0","id":"probe","result":{"fixture":true}}\n\n'


def attachment(
    url: str = "https://relay.fixture.invalid", local: bool = False
) -> human.SurfaceAttachment:
    return human.SurfaceAttachment(
        "surface_x",
        "session:one",
        human.SurfaceInvitation(
            relay_base_url=url,
            session_id="b3session",
            token="T" * 32,
            surface_id="board:fixture",
            application="Fixture",
            allow_insecure_loopback=local,
        ),
        human.Participant("agent:b3", "Fixture", "#fff"),
        "b3_client",
    )


class Http:
    def __init__(self) -> None:
        self.posts = 0
        self.streams = 0
        self.post_status = 200
        self.stream_status = 200
        self.body = ""

    def post(self, url: str, headers: Mapping[str, str], body: str) -> human.RelayResponse:
        self.posts += 1
        return human.RelayResponse(self.post_status, self.body)

    def stream(self, url: str, headers: Mapping[str, str]) -> human.RelayStream:
        self.streams += 1
        return human.RelayStream(self.stream_status, [RPC])


def transport(http: Http, **options: Any) -> human.SsePostRelayTransport:
    defaults: dict[str, Any] = {
        "allowed_relay_hosts": ["relay.fixture.invalid"],
        "egress_proxy": "http://proxy.fixture:3128",
    }
    defaults.update(options)
    return human.SsePostRelayTransport(http, **defaults)


@pytest.mark.parametrize("row", FIXTURE["statusRows"], ids=lambda row: row["id"])
def test_status_owns_category(row: dict[str, Any]) -> None:
    subject = transport(Http())
    # A classifier primitive: accepting 2xx does not claim a body exists on HTTP 204.
    if row["expected"] == "success":
        subject._assert_live(row["status"], row["body"], row["operation"] == "detach")
    else:
        with pytest.raises(human.HumanPlusError) as caught:
            subject._assert_live(row["status"], row["body"], row["operation"] == "detach")
        assert type(caught.value).__name__ == row["expected"]
        assert "PRIVATE-B3" not in str(caught.value)


@pytest.mark.parametrize(
    "row",
    [
        r
        for r in FIXTURE["statusRows"]
        if r["status"] in (401, 409, 410) and r["body"] != "PRIVATE-B3-not-session_gone"
    ],
    ids=lambda row: row["id"],
)
def test_actual_status_callsite(row: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Literal address must not resolve")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    http = Http()
    http.post_status = 200 if row["operation"] == "stream" else row["status"]
    http.stream_status = row["status"]
    http.body = row["body"]
    subject = transport(http, allowed_relay_hosts=["8.8.8.8"])
    caught = "success"
    try:
        if row["operation"] == "detach":
            subject.detach(attachment("https://8.8.8.8"))
        elif row["operation"] == "notify":
            subject.notify(attachment("https://8.8.8.8"), FRAME)
        else:
            subject.exchange(attachment("https://8.8.8.8"), FRAME)
    except human.HumanPlusError as error:
        caught = type(error).__name__
    assert caught == row["expected"]
    assert (http.posts, http.streams) == (1, 1 if row["operation"] == "stream" else 0)


@pytest.mark.parametrize("profile", FIXTURE["dnsProfiles"], ids=lambda row: row["id"])
def test_named_dns_per_leg(profile: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    http = Http()
    lookups: list[str] = []

    def lookup(host: str, port: Any, *args: Any, **kwargs: Any) -> Any:
        index = len(lookups)
        lookups.append(host)
        answer = profile["answers"][min(index, len(profile["answers"]) - 1)]
        if answer is False:
            raise socket.gaierror("PRIVATE-B3-DNS")
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (ip, 443, 0, 0) if ":" in ip else (ip, 443),
            )
            for ip in answer
        ]

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    subject = transport(
        http,
        allowed_relay_hosts=profile.get("allowedHosts", ["relay.fixture.invalid"]),
        allowed_relay_ports=profile.get("allowedPorts", [443]),
        egress_proxy=None if profile.get("proxy", True) is None else "http://proxy.fixture:3128",
        allow_unverified_egress=profile.get("allowUnverified", False),
    )
    item = attachment(
        profile.get("url", "https://relay.fixture.invalid"),
        profile.get("allowInsecureLoopback", False),
    )
    if profile["expectedPublic"]:
        assert subject.exchange(item, FRAME)["result"] == {"fixture": True}
    else:
        with pytest.raises(human.AttachmentUnauthorized) as refused:
            subject.exchange(item, FRAME)
        assert "PRIVATE-B3" not in str(refused.value)
    assert http.posts == profile.get("expectedPosts", 1 if profile["expectedPublic"] else 0)
    assert http.streams == profile.get("expectedStreams", 1 if profile["expectedPublic"] else 0)
    assert len(lookups) == profile.get(
        "expectedDnsCalls",
        2 if profile["id"] == "dns-rebind-before-get" or profile["expectedPublic"] else 1,
    )


@pytest.mark.parametrize("row", FIXTURE["addresses"], ids=lambda row: row["id"])
def test_literal_address_without_dns(row: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Literal address must not resolve")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    http = Http()
    host = f"[{row['address']}]" if ":" in row["address"] else row["address"]
    subject = transport(http, allowed_relay_hosts=[row["address"], host])
    public = row.get("publicAddress", row.get("expectedPublic"))
    if public:
        assert subject.exchange(attachment("https://" + host), FRAME)["result"] == {"fixture": True}
    else:
        with pytest.raises(human.AttachmentUnauthorized):
            subject.exchange(attachment("https://" + host), FRAME)
    assert http.posts == (1 if public else 0)


@pytest.mark.parametrize("operation", ["notify", "detach"])
def test_dns_failure_before_one_way_http(operation: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def failure(*args: Any, **kwargs: Any) -> Any:
        raise socket.gaierror("PRIVATE-B3-DNS")

    monkeypatch.setattr(socket, "getaddrinfo", failure)
    http = Http()
    with pytest.raises(human.AttachmentUnauthorized):
        if operation == "notify":
            transport(http).notify(attachment(), FRAME)
        else:
            transport(http).detach(attachment())
    assert (http.posts, http.streams) == (0, 0)
