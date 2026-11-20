"""
core/hybrid_mutator.py — Smart Hybrid Fuzzing (LLM Seed + Fast Mutation Engine).

Mô hình Fuzzing Lai (Hybrid Fuzzing):
1. Sử dụng LLM hoặc HAR Traffic để tạo ra "Hạt giống vàng" (Golden Seeds) có cấu trúc ngữ nghĩa hợp lệ.
2. Bộ đột biến cục bộ (Local Fast Mutator) nhân bản và biến dị các hạt giống này với tốc độ hàng nghìn request/giây
   (Zero Token Cost), kiểm thử các điều kiện biên, tràn số nguyên, format strings, type confusion và memory corruption.
"""

from __future__ import annotations

import copy
import random
from typing import Any

# Tập hợp các giá trị biên số học (Boundary & Integer Overflow)
NUMERIC_MUTATIONS: list[Any] = [
    0,
    -1,
    -2147483648,          # 32-bit signed min
    2147483647,           # 32-bit signed max
    4294967295,           # 32-bit unsigned max
    -9223372036854775808, # 64-bit signed min
    9223372036854775807,  # 64-bit signed max
    1e30,                 # Big float
    -1e30,
    0.0000000001,         # Precision underflow
    "NaN",
    "Infinity",
    "-Infinity",
]

# Tập hợp các chuỗi biên (String Boundary, Format Strings, Injection Delimiters)
STRING_MUTATIONS: list[str] = [
    "",                                # Chuỗi rỗng
    "A" * 5000,                        # Buffer / DoS payload
    "A" * 10000,
    "\x00",                            # Null Byte Injection
    "admin\x00.png",
    "%s%s%s%s%s%s%n",                 # Format string probe
    "{{7*7}}",                         # SSTI Jinja2 / Twig
    "${7*7}",                          # SSTI Spring / JSP
    "#{7*7}",                          # Ruby / EL injection
    "../../../../../../etc/passwd",     # Path Traversal Linux
    "..\\..\\..\\..\\windows\\win.ini",# Path Traversal Windows
    "'; WAITFOR DELAY '0:0:5'--",      # Time-based SQLi
    "1' OR '1'='1",
    "<svg onload=alert(1)>",           # XSS
    "\uFEFF\u200B\u200D",              # Zero-width spaces & BOM
    "\uff0f\uff0e\uff0e\uff0f",        # Unicode Path Normalization bypass
]

# Đột biến Type Confusion (Hoán đổi kiểu dữ liệu)
TYPE_CONFUSION_MUTATIONS: list[Any] = [
    True,
    False,
    None,
    [],
    {},
    [None],
    {"$ne": ""},                       # NoSQL Injection query object
    {"$gt": ""},
    {"__proto__": {"admin": True}},    # Prototype Pollution
    "true",
    "false",
    "null",
]


class HybridMutator:
    """Bộ biến dị cục bộ tốc độ cao dành cho Smart Hybrid Fuzzing."""

    def __init__(self, seed_ratio: float = 0.5) -> None:
        self.seed_ratio = seed_ratio

    def mutate_scalar(self, val: Any) -> list[Any]:
        """Biến dị một giá trị đơn (scalar: int, float, str, bool)."""
        mutations: list[Any] = []

        if isinstance(val, (int, float)) and not isinstance(val, bool):
            mutations.extend(NUMERIC_MUTATIONS[:6])
            # Thêm type confusion
            mutations.extend(["0", "NaN", None, True])
        elif isinstance(val, str):
            mutations.extend(STRING_MUTATIONS[:12])
            # Thêm các chuỗi đột biến đặc biệt
            mutations.extend([None, 0, -1, True, ["injected"]])
        elif isinstance(val, bool):
            mutations.extend([not val, "true", "false", 1, 0, None, "1"])
        else:
            mutations.extend([None, "", 0, {}, []])

        return mutations

    def mutate_dict_payload(self, base_payload: dict[str, Any], count: int = 5) -> list[dict[str, Any]]:
        """Nhân bản và biến dị một request body / dictionary DTO hợp lệ."""
        if not isinstance(base_payload, dict) or not base_payload:
            return [{}]

        results: list[dict[str, Any]] = []
        keys = list(base_payload.keys())

        for _ in range(count):
            clone = copy.deepcopy(base_payload)
            target_key = random.choice(keys)
            orig_val = clone[target_key]

            # 1. Đột biến giá trị của trường được chọn
            scalar_muts = self.mutate_scalar(orig_val)
            clone[target_key] = random.choice(scalar_muts)

            # 2. Xác suất 30% chèn thêm trường đặc quyền (Mass Assignment mutation)
            if random.random() < 0.3:
                priv_field = random.choice(["is_admin", "role", "verified", "balance", "permissions"])
                clone[priv_field] = random.choice([True, "admin", 999999, ["*"]])

            # 3. Xác suất 20% chèn Prototype Pollution
            if random.random() < 0.2:
                clone["__proto__"] = {"admin": True, "role": "superuser"}

            results.append(clone)

        return results

    def expand_fuzz_payloads(
        self,
        base_fuzz_items: list[dict[str, Any]],
        mutations_per_seed: int = 5,
    ) -> list[dict[str, Any]]:
        """Nhân bản danh sách Fuzz Items cơ sở thành bộ Fuzz Items đột biến lai quy mô lớn."""
        expanded: list[dict[str, Any]] = []

        for item in base_fuzz_items:
            # Giữ lại item gốc (Seed)
            expanded.append(item)

            val = item.get("payload_value")
            loc = str(item.get("param_location", "query")).lower()

            if loc == "body" and isinstance(val, dict):
                # Biến dị cấu trúc body DTO
                mutated_bodies = self.mutate_dict_payload(val, count=mutations_per_seed)
                for mb in mutated_bodies:
                    new_item = copy.deepcopy(item)
                    new_item["payload_value"] = mb
                    new_item["attack_type"] = f"{item.get('attack_type', 'fuzz')}_hybrid_mutation"
                    expanded.append(new_item)
            else:
                # Biến dị giá trị tham số đơn
                mut_vals = self.mutate_scalar(val)[:mutations_per_seed]
                for mv in mut_vals:
                    new_item = copy.deepcopy(item)
                    new_item["payload_value"] = mv
                    new_item["attack_type"] = f"{item.get('attack_type', 'fuzz')}_hybrid_mutation"
                    expanded.append(new_item)

        return expanded
