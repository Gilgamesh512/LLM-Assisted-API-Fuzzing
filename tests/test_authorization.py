from core.authorization import (
    AuthIdentity,
    HTTPObservation,
    RoleExpectation,
    WorkflowStep,
    check_authentication_matrix,
    check_bfla,
    check_bola,
    run_workflow,
)


def test_authentication_matrix_detects_invalid_token_bypass():
    findings = check_authentication_matrix(
        "/api/orders", "get",
        lambda token: HTTPObservation(200 if token != "expired-token" else 401),
    )
    assert {item.reproduction["credential_case"] for item in findings} == {"missing", "invalid"}
    assert all(item.vulnerability == "Broken Authentication" for item in findings)


def test_bola_detects_user_b_object_accessed_by_user_a():
    user_b = AuthIdentity("user-b", "token-b")
    user_a = AuthIdentity("user-a", "token-a")

    finding = check_bola(
        "/api/users/{id}", "get", user_b, user_a, "101",
        lambda identity, object_id: HTTPObservation(200, {"id": object_id}),
    )
    assert finding is not None
    assert finding.vulnerability == "Broken Object Level Authorization"
    assert finding.reproduction["attacker"] == "user-a"


def test_bfla_uses_role_matrix():
    identities = [AuthIdentity("admin", "a", "admin"), AuthIdentity("user", "u", "user")]
    findings = check_bfla(
        "/api/admin/users", "delete", identities,
        [RoleExpectation("admin", True), RoleExpectation("user", False)],
        lambda identity: HTTPObservation(200),
    )
    assert len(findings) == 1
    assert findings[0].reproduction["role"] == "user"


def test_stateful_workflow_carries_created_object_to_next_step():
    seen = []
    identity = AuthIdentity("user-a", "token-a")
    steps = [
        WorkflowStep("create", "POST", "/orders", lambda state, _: HTTPObservation(201, {"id": "order-1"}), "order"),
        WorkflowStep("get", "GET", "/orders/{id}", lambda state, _: (seen.append(state["order"]["id"]) or HTTPObservation(200)), None),
    ]
    result = run_workflow(steps, {"user-a": identity})
    assert result.state["order"]["id"] == "order-1"
    assert seen == ["order-1"]
    assert [name for name, _ in result.observations] == ["create", "get"]
