

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


class Matchers(BaseModel):
    status: list[int] = Field(default_factory=list)
    words: list[str] = Field(default_factory=list)
    regex: list[str] = Field(default_factory=list)
    dsl: list[str] = Field(default_factory=list)
    condition: Literal["or", "and"] = "or"

    def is_empty(self) -> bool:
        """True nếu không có matcher nào — template sẽ vô nghĩa, cần cảnh báo."""
        return not (self.status or self.words or self.regex or self.dsl)


class Case(BaseModel):
    """Một test case do LLM sinh, bám sát mẫu ở mục 5.2 CLAUDE.md."""

    id: str
    endpoint: str
    method: HttpMethod = "GET"
    vuln_type: str
    headers: dict[str, str] = Field(default_factory=dict)
    path_params: dict[str, Any] = Field(default_factory=dict)
    query_params: dict[str, Any] = Field(default_factory=dict)
    body: Optional[Any] = None
    payload: Optional[str] = None
    matchers: Matchers = Field(default_factory=Matchers)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"

    @field_validator("endpoint")
    @classmethod
    def _endpoint_must_start_with_slash(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError(f"endpoint phải bắt đầu bằng '/': {v!r}")
        return v

    @field_validator("id")
    @classmethod
    def _id_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("id không được rỗng")
        return v


class Suite(BaseModel):
    """Toàn bộ payload JSON module B gửi sang."""

    target: str
    test_cases: list[Case] = Field(min_length=1)
    variables: dict[str, str] = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def _target_is_http_url(cls, v: str) -> str:
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError(f"target phải là URL http(s)://: {v!r}")
        return v.rstrip("/")


class Finding(BaseModel):
    """Kết quả cho 1 test case sau khi chạy Nuclei."""

    id: str
    endpoint: str
    vuln_type: str
    matched: bool
    severity: str
    matched_at: Optional[str] = None
    response_status: Optional[int] = None
    evidence: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class Summary(BaseModel):
    total: int
    matched: int
    errors: int
    duration_sec: float


class ExecutorResult(BaseModel):
    """Đối tượng cuối cùng trả về pipeline."""

    target: str
    summary: Summary
    findings: list[Finding]
