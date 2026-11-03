from __future__ import annotations

from core.sanitizer import DataMasker, mask_spec_data, unmask_text, unmask_object


def test_data_masker_masks_internal_ip_and_domain():
    masker = DataMasker()
    input_text = "Connect to http://10.0.1.5:8080 or https://auth.corp.internal for user admin@company.com"
    masked = masker.mask_string(input_text)

    assert "10.0.1.5" not in masked
    assert "auth.corp.internal" not in masked
    assert "admin@company.com" not in masked
    assert "192.0.2." in masked
    assert "@example.mock" in masked

    unmasked = masker.unmask_string(masked)
    assert unmasked == input_text


def test_mask_spec_data_structure():
    spec = {
        "host": "api.intranet",
        "endpoints": [
            {
                "path": "/users",
                "sample_request": {"email": "boss@megacorp.com", "server_ip": "192.168.1.100"},
            }
        ],
    }
    masked_spec, reverse_map = mask_spec_data(spec)
    assert masked_spec["host"] != "api.intranet"
    assert masked_spec["endpoints"][0]["sample_request"]["email"] != "boss@megacorp.com"
    assert masked_spec["endpoints"][0]["sample_request"]["server_ip"] != "192.168.1.100"

    text_rep = str(masked_spec)
    restored = unmask_text(text_rep, reverse_map)
    assert "boss@megacorp.com" in restored
    assert "192.168.1.100" in restored


def test_unmask_object():
    reverse_map = {
        "user_1@example.mock": "admin@company.com",
        "api-service-1.example.com": "api.internal",
    }
    payloads = [
        {
            "method": "POST",
            "path": "/api-service-1.example.com/login",
            "payload_value": "user_1@example.mock",
            "nested": {"user": "user_1@example.mock"},
        }
    ]
    restored = unmask_object(payloads, reverse_map)
    assert restored[0]["path"] == "/api.internal/login"
    assert restored[0]["payload_value"] == "admin@company.com"
    assert restored[0]["nested"]["user"] == "admin@company.com"

