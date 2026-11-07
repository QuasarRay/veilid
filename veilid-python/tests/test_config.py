"""Config sections a cargo feature adds are optional. Needs no server."""

import json

from veilid import VeilidConfigAttachment, VeilidConfigProtocol, VeilidConfigWSS
from veilid.types import VeilidJSONEncoder

_UDP = {"enabled": True, "listen_address": "", "public_address": None}
_TCP = {"connect": True, "listen": True, "listen_address": "", "public_address": None}
_WS = {"connect": True, "listen": True, "listen_address": "", "path": "ws", "url": None}
_WSS = {"connect": True, "listen": False, "listen_address": "", "path": "ws", "url": None}
_WEBTRANSPORT = {"connect": True, "listen": True, "listen_address": "", "path": "wt", "url": None}


def test_feature_section_loads_as_its_class():
    protocol = VeilidConfigProtocol.from_json(
        {"udp": _UDP, "tcp": _TCP, "ws": _WS, "wss": _WSS, "webtransport": _WEBTRANSPORT}
    )
    assert isinstance(protocol.wss, VeilidConfigWSS)
    assert json.loads(VeilidJSONEncoder.dumps(protocol))["wss"]["path"] == "ws"


def test_feature_section_is_none_and_unsent_without_the_feature():
    # A core built without wss and webtransport leaves their keys out
    protocol = VeilidConfigProtocol.from_json({"udp": _UDP, "tcp": _TCP, "ws": _WS})
    assert protocol.wss is None
    assert protocol.webtransport is None

    # Sending null would break a core that has the feature; left out, the core applies its default
    sent = json.loads(VeilidJSONEncoder.dumps(protocol))
    assert "wss" not in sent
    assert "webtransport" not in sent

    attachment = VeilidConfigAttachment.from_json({})
    assert attachment.app_lifecycle is None
    assert "app_lifecycle" not in json.loads(VeilidJSONEncoder.dumps(attachment))


def test_unknown_keys_are_ignored():
    protocol = VeilidConfigProtocol.from_json(
        {"udp": _UDP, "tcp": _TCP, "ws": _WS, "future_protocol": {"connect": True}}
    )
    assert protocol == VeilidConfigProtocol.from_json({"udp": _UDP, "tcp": _TCP, "ws": _WS})
