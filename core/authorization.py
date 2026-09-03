"""Reusable authentication, authorization, BOLA, and stateful workflow checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class AuthIdentity:
    name: str
    token: str
    role: str = "user"


@dataclass(frozen=True)
class HTTPObservation:
    status_code: int
    body: Any = None
    evidence: str = ""


@dataclass
class AuthorizationFinding:
    vulnerability: str
    endpoint: str
    method: str
    severity: str
    confidence: int
    evidence: str
    reproduction: dict[str, Any]
    recommendation: str
    confirmed: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "vulnerability": self.vulnerability,
            "vuln_type": "BOLA" if "Object" in self.vulnerability else self.vulnerability,
            "endpoint": self.endpoint,
            "method": self.method,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "reproduction": self.reproduction,
            "recommendation": self.recommendation,
            "confirmed": self.confirmed,
        }


@dataclass(frozen=True)
class RoleExpectation:
    role: str
    allowed: bool


@dataclass
class WorkflowStep:
    name: str
    method: str
    endpoint: str
    request: Callable[[dict[str, Any], AuthIdentity], HTTPObservation]
    save_as: str | None = None


@dataclass
class WorkflowResult:
    state: dict[str, Any] = field(default_factory=dict)
    observations: list[tuple[str, HTTPObservation]] = field(default_factory=list)


def check_authentication_matrix(
    endpoint: str,
    method: str,
    request: Callable[[str | None], HTTPObservation],
) -> list[AuthorizationFinding]:
    """Check missing, invalid, and expired credentials; 2xx means a bypass."""
    cases = (("missing", None), ("invalid", "invalid-token"), ("expired", "expired-token"))
    findings: list[AuthorizationFinding] = []
    for label, token in cases:
        observation = request(token)
        if 200 <= observation.status_code < 300:
            findings.append(AuthorizationFinding(
                vulnerability="Broken Authentication",
                endpoint=endpoint,
                method=method.upper(),
                severity="high",
                confidence=90,
                evidence=f"{label} credential received HTTP {observation.status_code}. {observation.evidence}".strip(),
                reproduction={"credential_case": label, "status_code": observation.status_code},
                recommendation="Require valid, non-expired credentials and reject invalid tokens.",
            ))
    return findings


def check_bola(
    endpoint: str,
    method: str,
    owner: AuthIdentity,
    attacker: AuthIdentity,
    object_id: str,
    request: Callable[[AuthIdentity, str], HTTPObservation],
) -> AuthorizationFinding | None:
    """Report BOLA when another identity can read or mutate the owner's object."""
    owner_observation = request(owner, object_id)
    attacker_observation = request(attacker, object_id)
    if not (200 <= owner_observation.status_code < 300):
        return None
    if not (200 <= attacker_observation.status_code < 300):
        return None
    return AuthorizationFinding(
        vulnerability="Broken Object Level Authorization",
        endpoint=endpoint,
        method=method.upper(),
        severity="high",
        confidence=95,
        evidence=(f"{attacker.name} token accessed object {object_id} owned by {owner.name} "
                  f"with HTTP {attacker_observation.status_code}. {attacker_observation.evidence}").strip(),
        reproduction={
            "owner": owner.name,
            "attacker": attacker.name,
            "object_id": object_id,
            "owner_status": owner_observation.status_code,
            "attacker_status": attacker_observation.status_code,
        },
        recommendation="Enforce object-level authorization for every requested object.",
    )


def check_bfla(
    endpoint: str,
    method: str,
    identities: Iterable[AuthIdentity],
    expectations: Iterable[RoleExpectation],
    request: Callable[[AuthIdentity], HTTPObservation],
) -> list[AuthorizationFinding]:
    """Compare endpoint responses against an explicit role allow/deny matrix."""
    expected_by_role = {item.role: item.allowed for item in expectations}
    findings: list[AuthorizationFinding] = []
    for identity in identities:
        allowed = expected_by_role.get(identity.role)
        if allowed is None:
            continue
        observation = request(identity)
        actually_allowed = 200 <= observation.status_code < 300
        if actually_allowed != allowed:
            findings.append(AuthorizationFinding(
                vulnerability="Broken Function Level Authorization",
                endpoint=endpoint,
                method=method.upper(),
                severity="high",
                confidence=90,
                evidence=(f"role {identity.role!r} expected allowed={allowed} but received "
                          f"HTTP {observation.status_code}. {observation.evidence}").strip(),
                reproduction={"role": identity.role, "expected_allowed": allowed, "status_code": observation.status_code},
                recommendation="Enforce function-level authorization and deny unauthorized roles by default.",
            ))
    return findings


def run_workflow(steps: Iterable[WorkflowStep], identities: dict[str, AuthIdentity]) -> WorkflowResult:
    """Execute dependent API operations sequentially, carrying saved values forward."""
    state: dict[str, Any] = {}
    observations: list[tuple[str, HTTPObservation]] = []
    for step in steps:
        identity_name = next(iter(identities))
        observation = step.request(state, identities[identity_name])
        observations.append((step.name, observation))
        if not 200 <= observation.status_code < 300:
            break
        if step.save_as:
            state[step.save_as] = observation.body
    return WorkflowResult(state=state, observations=observations)
