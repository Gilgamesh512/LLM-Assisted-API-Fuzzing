from __future__ import annotations

from core.stateful_chain import ChainStep, StatefulContext, execute_chain


def test_stateful_context_template_replacement():
    ctx = StatefulContext({"user_id": 42, "role": "admin"})
    rendered = ctx.resolve_template("/api/users/{{user_id}}/roles/{role}")
    assert rendered == "/api/users/42/roles/admin"


def test_stateful_context_extraction():
    ctx = StatefulContext()
    response_payload = {
        "status": "success",
        "data": {
            "order": {
                "id": "ORD-999",
                "items": [{"name": "item1", "price": 10}],
            }
        },
        "token": "secret_jwt_xyz",
    }
    extracted = ctx.extract(
        response_payload,
        {
            "order_id": "data.order.id",
            "first_item": "data.order.items.0.name",
            "jwt_token": "token",
        },
    )
    assert extracted["order_id"] == "ORD-999"
    assert extracted["first_item"] == "item1"
    assert extracted["jwt_token"] == "secret_jwt_xyz"
    assert ctx.get("order_id") == "ORD-999"


def test_execute_chain_with_mock_requester():
    steps = [
        ChainStep(
            name="CreateOrder",
            method="POST",
            path="/api/orders",
            body={"item": "book"},
            extractors={"created_id": "id"},
        ),
        ChainStep(
            name="AccessOrderAsOtherUser",
            method="GET",
            path="/api/orders/{{created_id}}",
            expect_security_failure=True,  # BOLA test
        ),
    ]

    def mock_requester(method, url, headers, body, params):
        if method == "POST":
            return 201, {"id": "ORDER-101", "status": "created"}
        if method == "GET" and "ORDER-101" in url:
            # Server returns 200 instead of 403 -> BOLA vulnerability triggered!
            return 200, {"id": "ORDER-101", "owner": "victim"}
        return 404, {}

    results = execute_chain(steps, "http://testserver", requester=mock_requester)
    assert len(results) == 2
    assert results[0].step_name == "CreateOrder"
    assert results[0].extracted.get("created_id") == "ORDER-101"

    assert results[1].step_name == "AccessOrderAsOtherUser"
    assert results[1].executed_path == "/api/orders/ORDER-101"
    assert results[1].security_flag is True  # Detected BOLA!
    assert "BOLA / BFLA CONFIRMED" in results[1].evidence
