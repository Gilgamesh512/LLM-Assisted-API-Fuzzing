"""
core/compliance.py — Bản đồ Tuân thủ Chuẩn mực An ninh API Quốc tế (OWASP API Top 10 & CWE).

Cung cấp thông tin chuẩn hóa cho Cấp quản lý (CISO / Tech Lead / PM):
- Phân loại mọi lỗ hổng phát hiện được vào danh mục OWASP API Security Top 10 (2023) và mã định danh CWE (Common Weakness Enumeration).
- Đánh giá chỉ số tuân thủ tổng thể (Compliance Score %) cho toàn bộ ứng dụng API.
"""

from __future__ import annotations

from typing import Any

OWASP_API_TAXONOMY = {
    "API1:2023": {
        "title": "Broken Object Level Authorization (BOLA / IDOR)",
        "cwe": ["CWE-639", "CWE-284"],
        "severity": "critical",
        "description": "API không kiểm tra quyền sở hữu của người dùng đối với đối tượng được yêu cầu qua ID.",
        "remediation": "Triển khai kiểm tra phân quyền truy cập dựa trên phiên của người dùng ở cấp độ bản ghi (Object-level checks).",
    },
    "API2:2023": {
        "title": "Broken Authentication",
        "cwe": ["CWE-287", "CWE-306", "CWE-384"],
        "severity": "high",
        "description": "Cơ chế xác thực bị lỗi, token yếu, hoặc cho phép bypass qua các HTTP methods thay thế.",
        "remediation": "Củng cố cơ chế xác thực JWT/OAuth2, kiểm tra token trên tất cả các HTTP methods và áp dụng short-lived tokens.",
    },
    "API3:2023": {
        "title": "Broken Object Property Level Authorization (Mass Assignment)",
        "cwe": ["CWE-915", "CWE-213"],
        "severity": "high",
        "description": "Cho phép người dùng gán hoặc thay đổi các thuộc tính đặc quyền (role, balance, permissions) ngoài phạm vi.",
        "remediation": "Áp dụng DTO nghiêm ngặt với allowlist các thuộc tính được phép cập nhật; loại bỏ việc bind tự động.",
    },
    "API4:2023": {
        "title": "Unrestricted Resource Consumption",
        "cwe": ["CWE-770", "CWE-400"],
        "severity": "medium",
        "description": "Không giới hạn tần suất yêu cầu (Rate Limit), độ phức tạp của truy vấn hoặc kích thước tài nguyên.",
        "remediation": "Thiết lập Rate Limiting (RPS/IP/Token), giới hạn kích thước payload và timeout chặt chẽ.",
    },
    "API5:2023": {
        "title": "Broken Function Level Authorization (BFLA)",
        "cwe": ["CWE-285", "CWE-280"],
        "severity": "high",
        "description": "Người dùng thông thường có thể gọi được các API chức năng dành riêng cho quản trị viên (Admin endpoints).",
        "remediation": "Áp dụng RBAC (Role-Based Access Control) hoặc ABAC trên mọi endpoint nhạy cảm.",
    },
    "API6:2023": {
        "title": "Unrestricted Access to Sensitive Business Flows",
        "cwe": ["CWE-799"],
        "severity": "medium",
        "description": "Lỗ hổng logic cho phép tự động hóa hoặc lạm dụng các luồng nghiệp vụ quan trọng (mua hàng, voucher).",
        "remediation": "Phát hiện hành vi bất thường, sử dụng captcha/proof-of-work cho các luồng nhạy cảm.",
    },
    "API7:2023": {
        "title": "Server-Side Request Forgery (SSRF)",
        "cwe": ["CWE-918"],
        "severity": "high",
        "description": "API nhận URL từ người dùng và truy cập tài nguyên mạng nội bộ hoặc cloud metadata không an toàn.",
        "remediation": "Áp dụng allowlist domain/IP nghiêm ngặt cho các outbound requests, chặn hoàn toàn dải 169.254.169.254.",
    },
    "API8:2023": {
        "title": "Security Misconfiguration",
        "cwe": ["CWE-16", "CWE-693", "CWE-209"],
        "severity": "medium",
        "description": "Cấu hình bảo mật yếu: Bật phương thức TRACE (XST), chấp nhận header Method Override, hoặc lộ stack trace.",
        "remediation": "Tắt các phương thức HTTP không cần thiết, vô hiệu hóa X-HTTP-Method-Override và ẩn thông tin lỗi chi tiết.",
    },
    "API9:2023": {
        "title": "Improper Inventory Management",
        "cwe": ["CWE-1059"],
        "severity": "low",
        "description": "Để hở các phiên bản API cũ (Zombie APIs) hoặc các API nội bộ chưa được kiểm soát (Shadow APIs).",
        "remediation": "Tự động phát hiện và thu hồi các endpoint không còn sử dụng; áp dụng API Gateway tập trung.",
    },
    "API10:2023": {
        "title": "Unsafe Consumption of APIs",
        "cwe": ["CWE-20", "CWE-89"],
        "severity": "high",
        "description": "Tin tưởng mù quáng vào dữ liệu trả về từ các API bên thứ ba mà không kiểm tra tính hợp lệ.",
        "remediation": "Sanitize và validate mọi dữ liệu nhận từ dịch vụ bên thứ ba trước khi đưa vào logic nội bộ.",
    },
}


def map_vulnerability_to_compliance(vuln_type: str) -> dict[str, Any]:
    """Ánh xạ một loại lỗ hổng cụ thể sang chuẩn OWASP API 2023 và mã CWE tương ứng."""
    v_upper = str(vuln_type).upper()

    if any(k in v_upper for k in ("BOLA", "IDOR", "OBJECT LEVEL", "UNAUTHORIZED ACCESS")):
        category_id = "API1:2023"
        cwes = ["CWE-639", "CWE-284"]
    elif any(k in v_upper for k in ("JWT", "AUTH", "CREDENTIAL", "TOKEN", "SESSION")):
        category_id = "API2:2023"
        cwes = ["CWE-287", "CWE-306"]
    elif any(k in v_upper for k in ("MASS ASSIGNMENT", "PARAM", "PROPERTY", "ECHO-ONLY")):
        category_id = "API3:2023"
        cwes = ["CWE-915"]
    elif any(k in v_upper for k in ("RATE LIMIT", "DOS", "REDOS", "TIMEOUT", "RESOURCE")):
        category_id = "API4:2023"
        cwes = ["CWE-770", "CWE-400"]
    elif any(k in v_upper for k in ("BFLA", "FUNCTION LEVEL", "PRIVILEGE", "ROLE ESCALATION")):
        category_id = "API5:2023"
        cwes = ["CWE-285"]
    elif any(k in v_upper for k in ("SSRF", "METADATA")):
        category_id = "API7:2023"
        cwes = ["CWE-918"]
    elif any(k in v_upper for k in ("VERB", "TRACE", "METHOD OVERRIDE", "TUNNELING", "CONFIG", "LEAK", "STACK TRACE")):
        category_id = "API8:2023"
        cwes = ["CWE-16", "CWE-693"]
    elif any(k in v_upper for k in ("SQL", "INJECTION", "COMMAND", "TRAVERSAL", "XSS", "FILE")):
        category_id = "API10:2023"
        cwes = ["CWE-89", "CWE-78", "CWE-22"]
    else:
        category_id = "API8:2023"
        cwes = ["CWE-693"]

    meta = OWASP_API_TAXONOMY.get(category_id, {})
    return {
        "owasp_id": category_id,
        "owasp_title": meta.get("title", "API Security Finding"),
        "cwe_ids": cwes,
        "primary_cwe": cwes[0] if cwes else "CWE-693",
        "description": meta.get("description", ""),
        "remediation": meta.get("remediation", ""),
    }


def build_owasp_compliance_matrix(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Tổng hợp ma trận tuân thủ OWASP API Security Top 10 cho toàn bộ kết quả quét."""
    matrix: dict[str, dict[str, Any]] = {}

    for cat_id, info in OWASP_API_TAXONOMY.items():
        matrix[cat_id] = {
            "id": cat_id,
            "title": info["title"],
            "cwe": info["cwe"],
            "status": "PASSED",
            "findings_count": 0,
            "max_severity": "none",
            "description": info["description"],
            "remediation": info["remediation"],
        }

    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": -1}

    for f in findings:
        vuln = f.get("vuln_type") or f.get("vulnerability") or ""
        mapping = map_vulnerability_to_compliance(vuln)
        cat_id = mapping["owasp_id"]
        sev = str(f.get("severity", "info")).lower()

        if cat_id in matrix:
            entry = matrix[cat_id]
            entry["findings_count"] += 1
            if f.get("confirmed") or sev in ("critical", "high"):
                entry["status"] = "VIOLATED"
            elif entry["status"] != "VIOLATED" and entry["findings_count"] > 0:
                entry["status"] = "WARNING"

            curr_sev = entry["max_severity"]
            if sev_order.get(sev, 0) > sev_order.get(curr_sev, -1):
                entry["max_severity"] = sev

    violated_count = sum(1 for m in matrix.values() if m["status"] == "VIOLATED")
    warning_count = sum(1 for m in matrix.values() if m["status"] == "WARNING")
    passed_count = sum(1 for m in matrix.values() if m["status"] == "PASSED")
    compliance_score = round((passed_count / len(OWASP_API_TAXONOMY)) * 100, 1)

    return {
        "compliance_score": compliance_score,
        "total_categories": len(OWASP_API_TAXONOMY),
        "passed_categories": passed_count,
        "violated_categories": violated_count,
        "warning_categories": warning_count,
        "matrix": list(matrix.values()),
    }
