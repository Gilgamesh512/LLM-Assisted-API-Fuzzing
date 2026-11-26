"""
core/remediation.py — AI-Driven Automated Remediation & Patch Generation Engine.

Cung cấp giải pháp sửa lỗi bảo mật tự động, mã nguồn mẫu trước/sau (Code Patch),
và khuyến nghị kỹ thuật theo chuẩn Defense-in-Depth cho các kỹ sư phát triển phần mềm (Dev & DevOps).
Hỗ trợ đa ngôn ngữ/framework: Python (FastAPI/Flask/Django), Node.js (Express), Java (Spring Boot).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


FRAMEWORK_PATCH_TEMPLATES: dict[str, dict[str, dict[str, str]]] = {
    "bola": {
        "fastapi": {
            "title": "Bổ sung kiểm tra quyền sở hữu Object-Level trong FastAPI",
            "vulnerable": (
                "@app.get('/api/orders/{order_id}')\n"
                "async def get_order(order_id: int, db: Session = Depends(get_db)):\n"
                "    return db.query(Order).filter(Order.id == order_id).first()  # VULNERABLE: Không kiểm tra user sở hữu"
            ),
            "remediation": (
                "@app.get('/api/orders/{order_id}')\n"
                "async def get_order(order_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):\n"
                "    order = db.query(Order).filter(Order.id == order_id, Order.owner_id == current_user.id).first()\n"
                "    if not order:\n"
                "        raise HTTPException(status_code=404, detail='Order not found or access denied')\n"
                "    return order"
            ),
        },
        "express": {
            "title": "Bổ sung middleware xác thực phân quyền bản ghi trong Express.js",
            "vulnerable": (
                "app.get('/api/orders/:orderId', async (req, res) => {\n"
                "  const order = await Order.findById(req.params.orderId);\n"
                "  res.json(order);\n"
                "});"
            ),
            "remediation": (
                "app.get('/api/orders/:orderId', authenticateToken, async (req, res) => {\n"
                "  const order = await Order.findOne({ _id: req.params.orderId, ownerId: req.user.id });\n"
                "  if (!order) return res.status(404).json({ error: 'Order not found or unauthorized' });\n"
                "  res.json(order);\n"
                "});"
            ),
        },
        "spring_boot": {
            "title": "Áp dụng Spring Security @PreAuthorize / Object Ownership",
            "vulnerable": (
                "@GetMapping('/orders/{id}')\n"
                "public Order getOrder(@PathVariable Long id) {\n"
                "    return orderRepository.findById(id).orElseThrow();\n"
                "}"
            ),
            "remediation": (
                "@GetMapping('/orders/{id}')\n"
                "public Order getOrder(@PathVariable Long id, @AuthenticationPrincipal UserPrincipal user) {\n"
                "    return orderRepository.findByIdAndOwnerId(id, user.getId())\n"
                "        .orElseThrow(() -> new ResourceNotFoundException('Order not found'));\n"
                "}"
            ),
        },
    },
    "mass_assignment": {
        "fastapi": {
            "title": "Sử dụng Pydantic DTO nghiêm ngặt với extra='forbid'",
            "vulnerable": (
                "# DTO cho phép gán thuộc tính tùy ý\n"
                "class UserUpdate(BaseModel):\n"
                "    email: str | None = None\n"
                "    # Model cho phép nhận bất kỳ trường nào (kể cả role, is_admin)"
            ),
            "remediation": (
                "from pydantic import BaseModel, ConfigDict\n\n"
                "class UserUpdateDTO(BaseModel):\n"
                "    model_config = ConfigDict(extra='forbid')  # Chặn đứng mọi trường ngoài danh sách\n"
                "    display_name: str | None = None\n"
                "    bio: str | None = None\n"
                "    # Tuyệt đối không đưa role, is_admin, balance vào DTO này"
            ),
        },
        "express": {
            "title": "Lọc whitelist các thuộc tính cho phép cập nhật",
            "vulnerable": (
                "// Nguy hiểm: Cập nhật trực tiếp toàn bộ req.body vào DB\n"
                "await User.findByIdAndUpdate(req.user.id, req.body);"
            ),
            "remediation": (
                "const ALLOWED_UPDATES = ['displayName', 'bio', 'avatarUrl'];\n"
                "const safeUpdates = Object.keys(req.body)\n"
                "  .filter(key => ALLOWED_UPDATES.includes(key))\n"
                "  .reduce((obj, key) => { obj[key] = req.body[key]; return obj; }, {});\n"
                "await User.findByIdAndUpdate(req.user.id, { $set: safeUpdates }, { runValidators: true });"
            ),
        },
        "spring_boot": {
            "title": "Sử dụng DTO chuyên biệt thay vì Entity trực tiếp",
            "vulnerable": (
                "@PutMapping('/users/profile')\n"
                "public User updateProfile(@RequestBody User user) { // Nguy hiểm: Bind thẳng vào Entity JPA\n"
                "    return userRepository.save(user);\n"
                "}"
            ),
            "remediation": (
                "@PutMapping('/users/profile')\n"
                "public ResponseEntity<?> updateProfile(@Valid @RequestBody ProfileUpdateDto dto, @AuthenticationPrincipal UserPrincipal user) {\n"
                "    User existing = userRepository.findById(user.getId()).orElseThrow();\n"
                "    existing.setDisplayName(dto.getDisplayName());\n"
                "    return ResponseEntity.ok(userRepository.save(existing));\n"
                "}"
            ),
        },
    },
    "sqli": {
        "fastapi": {
            "title": "Sử dụng Parameterized Query / ORM thay cho nối chuỗi SQL thô",
            "vulnerable": (
                "query = f\"SELECT * FROM users WHERE username = '{username}'\"  # SQL Injection\n"
                "db.execute(text(query))"
            ),
            "remediation": (
                "# Sử dụng SQLAlchemy bind parameters an toàn:\n"
                "stmt = text(\"SELECT * FROM users WHERE username = :uname\")\n"
                "db.execute(stmt, {\"uname\": username})"
            ),
        },
        "express": {
            "title": "Sử dụng tham số hóa truy vấn cơ sở dữ liệu (Prepared Statements)",
            "vulnerable": (
                "const sql = `SELECT * FROM products WHERE category = '${req.query.cat}'`;\n"
                "const results = await db.query(sql);"
            ),
            "remediation": (
                "// Sử dụng Prepared Statement:\n"
                "const sql = 'SELECT * FROM products WHERE category = $1';\n"
                "const results = await db.query(sql, [req.query.cat]);"
            ),
        },
        "spring_boot": {
            "title": "Sử dụng Spring Data JPA @Query với Named Parameters",
            "vulnerable": (
                "String sql = \"SELECT * FROM users WHERE email = '\" + email + \"'\";\n"
                "entityManager.createNativeQuery(sql).getResultList();"
            ),
            "remediation": (
                "@Query(\"SELECT u FROM User u WHERE u.email = :email\")\n"
                "Optional<User> findByEmailSafe(@Param(\"email\") String email);"
            ),
        },
    },
    "jwt": {
        "fastapi": {
            "title": "Cấu hình xác thực JWT RFC 7519 nghiêm ngặt với PyJWT",
            "vulnerable": (
                "# Không giới hạn algorithm hoặc dùng verify_signature=False\n"
                "payload = jwt.decode(token, options={\"verify_signature\": False})"
            ),
            "remediation": (
                "import jwt\n\n"
                "# Bắt buộc thuật toán HS256/RS256 và xác thực thời hạn exp:\n"
                "try:\n"
                "    payload = jwt.decode(\n"
                "        token,\n"
                "        SECRET_KEY,\n"
                "        algorithms=[\"HS256\"],  # Chặn 'none'\n"
                "        options={\"require\": [\"exp\", \"sub\"], \"verify_signature\": True}\n"
                "    )\n"
                "except jwt.PyJWTError:\n"
                "    raise HTTPException(status_code=401, detail='Token không hợp lệ hoặc đã hết hạn')"
            ),
        },
        "express": {
            "title": "Xác thực JWT với jsonwebtoken (Chặn alg 'none')",
            "vulnerable": (
                "const decoded = jwt.decode(token); // Không verify chữ ký"
            ),
            "remediation": (
                "jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] }, (err, user) => {\n"
                "  if (err) return res.status(401).json({ error: 'Token invalid or expired' });\n"
                "  req.user = user;\n"
                "  next();\n"
                "});"
            ),
        },
        "spring_boot": {
            "title": "Cấu hình Nimbus / Spring Security JWT Validator",
            "vulnerable": (
                "// Chấp nhận mọi thuật toán header không kiểm định"
            ),
            "remediation": (
                "@Bean\n"
                "public JwtDecoder jwtDecoder() {\n"
                "    NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey)\n"
                "        .macAlgorithm(MacAlgorithm.HS256)\n"
                "        .build();\n"
                "    OAuth2TokenValidator<Jwt> withClock = new JwtTimestampValidator(Duration.ofSeconds(60));\n"
                "    decoder.setJwtValidator(withClock);\n"
                "    return decoder;\n"
                "}"
            ),
        },
    },
    "ssrf": {
        "fastapi": {
            "title": "Chặn phân giải IP nội bộ / Metadata Endpoint khi gửi Outgoing Request",
            "vulnerable": (
                "resp = requests.get(user_provided_url)  # SSRF vào 169.254.169.254 hoặc localhost"
            ),
            "remediation": (
                "import ipaddress, socket, urllib.parse\n\n"
                "def is_safe_url(url: str) -> bool:\n"
                "    parsed = urllib.parse.urlparse(url)\n"
                "    if parsed.scheme not in ('http', 'https'):\n"
                "        return False\n"
                "    ip_str = socket.gethostbyname(parsed.hostname)\n"
                "    ip = ipaddress.ip_address(ip_str)\n"
                "    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)\n\n"
                "if not is_safe_url(target_url):\n"
                "    raise HTTPException(status_code=400, detail='URL đích bị chặn do rủi ro mạng nội bộ')"
            ),
        },
        "express": {
            "title": "Áp dụng DNS Rebinding & Private IP validation",
            "vulnerable": (
                "const resp = await axios.get(req.body.webhookUrl);"
            ),
            "remediation": (
                "const ip = require('ip');\n"
                "const dns = require('dns').promises;\n\n"
                "const hostname = new URL(url).hostname;\n"
                "const { address } = await dns.lookup(hostname);\n"
                "if (ip.isPrivate(address) || ip.isLoopback(address)) {\n"
                "  throw new Error('SSRF Blocked: Private IP ranges are prohibited');\n"
                "}"
            ),
        },
        "spring_boot": {
            "title": "Khởi tạo RestTemplate với Custom RequestFactory chống SSRF",
            "vulnerable": (
                "restTemplate.getForObject(targetUrl, String.class);"
            ),
            "remediation": (
                "// Xác thực hostname và chặn dải IP 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254\n"
                "InetAddress address = InetAddress.getByName(uri.getHost());\n"
                "if (address.isSiteLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()) {\n"
                "    throw new SecurityException(\"Access to internal network is forbidden\");\n"
                "}"
            ),
        },
    },
    "graphql_dos": {
        "fastapi": {
            "title": "Giới hạn độ sâu truy vấn (Query Depth Limiting) trong GraphQL",
            "vulnerable": (
                "# Cho phép lồng query tùy ý (author -> posts -> author -> posts...)\n"
                "schema = strawberry.Schema(query=Query)"
            ),
            "remediation": (
                "from strawberry.extensions import MaxAliasesLimiter, MaxTokensLimiter\n"
                "# Giới hạn query depth và execution timeout:\n"
                "schema = strawberry.Schema(\n"
                "    query=Query,\n"
                "    extensions=[\n"
                "        MaxTokensLimiter(max_tokens=1000),\n"
                "    ]\n"
                ")"
            ),
        },
        "express": {
            "title": "Sử dụng graphql-depth-limit middleware",
            "vulnerable": (
                "app.use('/graphql', graphqlHTTP({ schema }));"
            ),
            "remediation": (
                "const depthLimit = require('graphql-depth-limit');\n"
                "app.use('/graphql', graphqlHTTP({\n"
                "  schema,\n"
                "  validationRules: [depthLimit(5)] // Giới hạn tối đa 5 tầng lồng nhau\n"
                "}));"
            ),
        },
        "spring_boot": {
            "title": "Cấu hình maxQueryDepth trong Spring for GraphQL",
            "vulnerable": (
                "// Cấu hình mặc định không giới hạn depth"
            ),
            "remediation": (
                "// Trong application.yml:\n"
                "spring:\n"
                "  graphql:\n"
                "    schema:\n"
                "      inspection:\n"
                "        enabled: true\n"
                "// Hoặc thêm MaxQueryDepthInstrumentation bean (tối đa 5 tầng)"
            ),
        },
    },
}


def _classify_vuln_category(vuln_type: str, evidence: str = "") -> str:
    """Xác định danh mục lỗ hổng để gắn template vá lỗi phù hợp."""
    v_low = vuln_type.lower()
    e_low = evidence.lower()

    if "bola" in v_low or "idor" in v_low or "broken object level" in v_low or "cwe-639" in v_low:
        return "bola"
    if (
        "mass assignment" in v_low
        or "mass_assignment" in v_low
        or "parameter tampering" in v_low
        or "property level" in v_low
        or "cwe-915" in v_low
    ):
        return "mass_assignment"
    if "sql" in v_low or "sqli" in v_low or "cwe-89" in v_low or "syntax error" in e_low:
        return "sqli"
    if "jwt" in v_low or "token" in v_low or "alg:none" in v_low or "cwe-287" in v_low:
        return "jwt"
    if "ssrf" in v_low or "callback" in v_low or "cwe-918" in v_low:
        return "ssrf"
    if "graphql" in v_low or "query depth" in v_low or "introspection" in v_low:
        return "graphql_dos"
    return "bola"


def generate_remediation(
    finding: dict[str, Any],
    framework: str = "auto",
    llm_provider: Any = None,
) -> dict[str, Any]:
    """Sinh khuyến nghị khắc phục và mã nguồn vá lỗi (Patch) cho 1 finding cụ thể."""
    vuln_type = str(finding.get("vuln_type") or finding.get("vulnerability") or "Unknown Vulnerability")
    endpoint = str(finding.get("endpoint", "/"))
    param = str(finding.get("target_param") or finding.get("param") or "id")
    evidence = str(finding.get("evidence", ""))
    severity = str(finding.get("severity", "medium")).lower()

    cat = _classify_vuln_category(vuln_type, evidence)
    cat_templates = FRAMEWORK_PATCH_TEMPLATES.get(cat, FRAMEWORK_PATCH_TEMPLATES["bola"])

    fw_key = framework.lower()
    if fw_key not in ("fastapi", "express", "spring_boot"):
        fw_key = "fastapi"  # Mặc định chuẩn Python hiện đại

    patch_info = cat_templates.get(fw_key, list(cat_templates.values())[0])

    # Nếu có LLM provider, có thể tùy biến prompt (nếu muốn)
    custom_note = ""
    if llm_provider and hasattr(llm_provider, "generate_payloads"):
        pass

    return {
        "finding_id": f"{endpoint}_{param}_{vuln_type}",
        "endpoint": endpoint,
        "method": finding.get("method", "GET"),
        "target_param": param,
        "vuln_type": vuln_type,
        "severity": severity,
        "framework": fw_key,
        "title": patch_info["title"],
        "category": cat,
        "vulnerable_code_snippet": patch_info["vulnerable"],
        "remediation_code_patch": patch_info["remediation"],
        "defense_in_depth": [
            "Áp dụng nguyên tắc đặc quyền tối thiểu (Principle of Least Privilege).",
            "Luôn xác thực và chuẩn hóa toàn bộ dữ liệu đầu vào (Input Validation & DTO Whitelist).",
            "Đảm bảo cơ chế logging ghi nhận lại mọi hành vi cố ý vi phạm quyền truy cập.",
        ],
    }


def generate_all_remediations(
    findings: list[dict[str, Any]],
    framework: str = "auto",
    llm_provider: Any = None,
) -> list[dict[str, Any]]:
    """Tạo danh sách hướng dẫn sửa lỗi cho toàn bộ các phát hiện (loại bỏ trùng lặp)."""
    seen: set[str] = set()
    results: list[dict[str, Any]] = []

    for f in findings:
        # Chỉ sinh remediation cho các finding đã xác nhận hoặc có mức độ medium trở lên
        sev = str(f.get("severity", "")).lower()
        if sev not in ("critical", "high", "medium"):
            continue
        key = f"{f.get('endpoint')}_{f.get('target_param')}_{f.get('vuln_type')}"
        if key in seen:
            continue
        seen.add(key)

        rem = generate_remediation(f, framework=framework, llm_provider=llm_provider)
        results.append(rem)

    return results


def export_remediations_markdown(remediations: list[dict[str, Any]], target_name: str = "") -> str:
    """Định dạng toàn bộ hướng dẫn sửa lỗi thành file Markdown chuyên nghiệp."""
    lines: list[str] = [
        f"# 🛡️ BÁO CÁO KHUYẾN NGHỊ VÁ LỖI BẢO MẬT (AI REMEDIATION PLAN)",
        f"**Mục tiêu ứng dụng:** {target_name or 'Hệ thống API'}",
        f"**Tổng số phát hiện cần khắc phục:** {len(remediations)}",
        "",
        "> Báo cáo này cung cấp mã nguồn vá lỗi (Patch Code) và cơ chế phòng vệ chi tiết",
        "> giúp lập trình viên (Developers) khắc phục triệt để các lỗ hổng mà không làm gián đoạn luồng nghiệp vụ.",
        "",
        "---",
        "",
    ]

    for idx, r in enumerate(remediations, 1):
        sev_badge = "🔴 CRITICAL" if r["severity"] == "critical" else ("🟠 HIGH" if r["severity"] == "high" else "🟡 MEDIUM")
        fw = str(r.get("framework", "fastapi")).lower()
        code_lang = "javascript" if fw == "express" else ("java" if fw == "spring_boot" else "python")
        lines.extend([
            f"## {idx}. [{sev_badge}] {r['vuln_type']} tại `{r['method']} {r['endpoint']}`",
            f"- **Tham số rủi ro:** `{r['target_param']}`",
            f"- **Framework áp dụng mẫu:** `{r['framework']}`",
            f"- **Chủ đề giải pháp:** {r['title']}",
            "",
            "### ❌ Mã nguồn dễ bị tấn công (Vulnerable Pattern):",
            f"```{code_lang}",
            r["vulnerable_code_snippet"],
            "```",
            "",
            "### ✅ Mã nguồn vá lỗi đề xuất (Remediated Code Patch):",
            f"```{code_lang}",
            r["remediation_code_patch"],
            "```",
            "",
            "### 🛡️ Nguyên tắc phòng thủ đa lớp (Defense-in-Depth):",
        ])
        for step in r["defense_in_depth"]:
            lines.append(f"- {step}")
        lines.append("\n---\n")

    return "\n".join(lines)


def export_remediations_file(
    remediations: list[dict[str, Any]],
    out_json: Path | str,
    out_md: Path | str,
    target_name: str = "",
) -> tuple[Path, Path]:
    """Xuất khuyến nghị sửa lỗi ra cả 2 định dạng JSON và Markdown."""
    pj = Path(out_json)
    pm = Path(out_md)
    pj.parent.mkdir(parents=True, exist_ok=True)
    pm.parent.mkdir(parents=True, exist_ok=True)

    pj.write_text(json.dumps(remediations, indent=2, ensure_ascii=False), encoding="utf-8")
    md_content = export_remediations_markdown(remediations, target_name=target_name)
    pm.write_text(md_content, encoding="utf-8")

    return pj, pm
