"""RESTCONF oper-data reader."""

import httpx
import pytest

from app.devices.base import DeviceError
from app.devices.restconf import OPER_PATH, RestconfReader

PAYLOAD = {
    "Cisco-IOS-XE-crypto-pki-oper:crypto-pki-bundle": [
        {
            "label": "HT-WxCAutoCert-A",
            "cert": [
                {
                    "subject-name": "cn=vg01.husd.clients.example.com,o=HyeTech",
                    "serial-number": "0a1b2c3d",
                    "validity-start": "2026-08-01T12:00:00+00:00",
                    "validity-end": "2026-10-30T12:00:00+00:00",
                }
            ],
        },
        {"label": "HT-WxCAutoCert-B"},
    ]
}


def _reader(handler, **kwargs) -> RestconfReader:
    client = httpx.Client(
        base_url="https://device.invalid", transport=httpx.MockTransport(handler)
    )
    return RestconfReader("device.invalid", "u", "p", client=client, **kwargs)


def test_reads_trustpoint_state():
    def handler(request):
        assert request.url.path == OPER_PATH
        return httpx.Response(200, json=PAYLOAD)

    state = _reader(handler).read_state()
    tp = state.trustpoints["HT-WxCAutoCert-A"]

    assert tp.has_certificate is True
    assert tp.subject_cn == "vg01.husd.clients.example.com"
    assert tp.serial == "0A1B2C3D"  # normalised to uppercase for comparison
    assert tp.validity_end.month == 10


def test_empty_trustpoint_is_reported_without_certificate():
    def handler(request):
        return httpx.Response(200, json=PAYLOAD)

    state = _reader(handler).read_state()
    assert state.get("HT-WxCAutoCert-B").has_certificate is False


def test_serial_matching_against_issued_certificate():
    def handler(request):
        return httpx.Response(200, json=PAYLOAD)

    tp = _reader(handler).read_state().trustpoints["HT-WxCAutoCert-A"]
    assert tp.matches("vg01.husd.clients.example.com", "0A1B2C3D") is True
    assert tp.matches("vg01.husd.clients.example.com", "FFFFFFFF") is False


def test_single_bundle_returned_as_dict():
    """RESTCONF collapses a one-element list to an object on some releases."""

    def handler(request):
        return httpx.Response(
            200,
            json={
                "Cisco-IOS-XE-crypto-pki-oper:crypto-pki-bundle": {
                    "label": "TP-1",
                    "cert": {
                        "subject-name": "cn=vg01.example.com",
                        "serial-number": "AB",
                        "validity-end": "2026-10-30T12:00:00Z",
                    },
                }
            },
        )

    state = _reader(handler).read_state()
    assert state.trustpoints["TP-1"].subject_cn == "vg01.example.com"


def test_missing_model_raises_so_caller_can_fall_back_to_cli():
    def handler(request):
        return httpx.Response(404, json={})

    with pytest.raises(DeviceError, match="not available"):
        _reader(handler).read_state()


def test_http_error_is_surfaced():
    def handler(request):
        return httpx.Response(401, json={})

    with pytest.raises(DeviceError, match="HTTP 401"):
        _reader(handler).read_state()


def test_zulu_timestamps_are_parsed():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "Cisco-IOS-XE-crypto-pki-oper:crypto-pki-bundle": [
                    {
                        "label": "TP",
                        "cert": [
                            {
                                "subject-name": "cn=x.example.com",
                                "serial-number": "01",
                                "validity-end": "2026-10-30T12:00:00Z",
                            }
                        ],
                    }
                ]
            },
        )

    tp = _reader(handler).read_state().trustpoints["TP"]
    assert tp.validity_end.year == 2026
    assert tp.validity_end.tzinfo is not None
