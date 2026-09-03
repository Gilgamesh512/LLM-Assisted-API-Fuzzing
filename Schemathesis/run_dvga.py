#!/usr/bin/env python3

import json
import os
import sys
import time
import uuid
from pathlib import Path
import requests

BASE_DIR = Path(__file__).resolve().parent

DVGA_URL = "http://localhost:5013"
GRAPHQL_URL = f"{DVGA_URL}/graphql"
OUTPUT_FILE = str(BASE_DIR / "dvga_schema.json")
ENV_FILE = BASE_DIR / "tokens.env"

MAX_RETRIES = 12
RETRY_DELAY = 3

INTROSPECTION_QUERY = """
query IntrospectionQuery {
    __schema {
        queryType {
            name
            fields {
                name
                description
                args {
                    name
                    description
                    type {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                            }
                        }
                    }
                    defaultValue
                }
                type {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                        }
                    }
                }
            }
        }
        mutationType {
            name
            fields {
                name
                description
                args {
                    name
                    description
                    type {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                            }
                        }
                    }
                    defaultValue
                }
                type {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                        }
                    }
                }
            }
        }
        types {
            kind
            name
            description
            fields {
                name
                description
                args {
                    name
                    type {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                            }
                        }
                    }
                }
                type {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                        }
                    }
                }
            }
            inputFields {
                name
                description
                type {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                        }
                    }
                }
                defaultValue
            }
            enumValues {
                name
                description
            }
        }
    }
}
"""

def wait_for_dvga():
    print("\n[*] Waiting for DVGA...")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(DVGA_URL, timeout=5)
            print(f"    [+] DVGA reachable (HTTP {response.status_code})")
            return True
        except requests.RequestException:
            print(f"    [-] DVGA not ready ({attempt}/{MAX_RETRIES})")
            time.sleep(RETRY_DELAY)
    return False

def graphql_request(query: str, variables: dict = None, headers: dict = None):
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    try:
        return requests.post(GRAPHQL_URL, json={"query": query, "variables": variables or {}}, headers=req_headers, timeout=10)
    except Exception as e:
        print(f"    [X] Network error: {e}")
        return None

def dynamic_register_and_login():
    """Tự động sinh tài khoản ngẫu nhiên, đăng ký và login lấy access token."""
    print("\n[*] DVGA DYNAMIC AUTH & AUTO-PROVISIONING...")

    # 1. Sinh thông tin tài khoản duy nhất (Unique)
    uid = uuid.uuid4().hex[:6]
    username = f"fuzzer_{uid}"
    password = f"Pass_{uid}!"
    email = f"{username}@test.lab"

    print(f"    [*] Đang tạo tài khoản mới: {username}")

    # 2. Gửi mutation createUser
    create_user_query = """
    mutation CreateUser($userData: UserInput!) {
        createUser(userData: $userData) {
            user {
                username
            }
        }
    }
    """
    res_reg = graphql_request(create_user_query, {
        "userData": {
            "username": username,
            "password": password,
            "email": email
        }
    })

    if res_reg is None or res_reg.status_code != 200:
        print("    [!] Đăng ký qua createUser thất bại, tiếp tục thử login...")
    else:
        print(f"    [+] Đăng ký tài khoản '{username}' thành công!")

    # 3. Đăng nhập lấy JWT Access Token
    login_query = """
    mutation Login($username: String!, $password: String!) {
        login(username: $username, password: $password) {
            accessToken
            refreshToken
        }
    }
    """
    res_login = graphql_request(login_query, {"username": username, "password": password})
    
    if res_login is None:
        print("    [X] Không nhận được phản hồi từ server khi đăng nhập.")
        return None

    try:
        payload = res_login.json()
    except Exception:
        print(f"    [X] Phản hồi không phải JSON: {res_login.text}")
        return None

    data_field = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data_field, dict):
        login_field = data_field.get("login")
        if isinstance(login_field, dict):
            token = login_field.get("accessToken")
            if token:
                print("    [+] LOGIN SUCCESS: Đã lấy JWT Token thành công!")
                return str(token)

    errors = payload.get("errors") if isinstance(payload, dict) else None
    if errors:
        print(f"    [X] Login thất bại: {errors}")
    return None

def update_dvga_token_env(token: str):
    """Ghi token vào file tokens.env"""
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    key = "DVGA_AUTH_HEADER"
    value = f"Authorization: Bearer {token}"
    output = [line for line in lines if not line.strip().startswith(f"export {key}=")]
    output.append(f'export {key}="{value}"')

    ENV_FILE.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        pass
    print(f"[+] Token đã được lưu vào {ENV_FILE}")

def introspect(auth_header: str = None):
    print("\n[*] Running GraphQL introspection...")
    headers = {"Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header

    try:
        response = requests.post(
            GRAPHQL_URL,
            json={"query": INTROSPECTION_QUERY},
            headers=headers,
            timeout=15,
        )
    except requests.RequestException as exc:
        print(f"[X] GraphQL connection error: {exc}")
        return None

    print(f"    HTTP {response.status_code}")

    try:
        data = response.json()
    except ValueError:
        print("[X] GraphQL did not return JSON.")
        return None

    if "errors" in data:
        print(f"[X] GraphQL introspection returned errors: {json.dumps(data['errors'], indent=2)}")
        return None

    if "data" not in data:
        print("[X] Missing data field.")
        return None

    return data

def analyze_schema(data):
    schema = data.get("data", {}).get("__schema", {})
    query_type = schema.get("queryType")
    mutation_type = schema.get("mutationType")

    queries = [field["name"] for field in query_type.get("fields", [])] if query_type else []
    mutations = [field["name"] for field in mutation_type.get("fields", [])] if mutation_type else []

    return {
        "query_type": query_type.get("name") if query_type else None,
        "mutation_type": mutation_type.get("name") if mutation_type else None,
        "queries": queries,
        "mutations": mutations,
        "type_count": len(schema.get("types", [])),
    }

def save_schema(data, analysis):
    artifact = {
        "target": "dvga",
        "protocol": "graphql",
        "base_url": DVGA_URL,
        "graphql_url": GRAPHQL_URL,
        "analysis": analysis,
        "schema": data,
    }
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)

def main():
    print("=" * 60)
    print(" DVGA GRAPHQL DISCOVERY & DYNAMIC AUTH")
    print("=" * 60)

    # 1. Kiểm tra DVGA
    if not wait_for_dvga():
        print("[X] DVGA unavailable.")
        sys.exit(1)

    # 2. Tự động sinh user, đăng ký và login lấy token
    token = dynamic_register_and_login()
    auth_header = None
    if token:
        update_dvga_token_env(token)
        auth_header = f"Bearer {token}"
    else:
        print("[!] Không lấy được token, tiếp tục chạy discovery không header...")

    # 3. Introspect Schema
    data = introspect(auth_header)
    if data is None:
        sys.exit(1)

    # 4. Phân tích và lưu Schema
    analysis = analyze_schema(data)

    print("\n[*] GraphQL Schema")
    print(f"    Query type    : {analysis['query_type']}")
    print(f"    Mutation type : {analysis['mutation_type']}")
    print(f"    Total types   : {analysis['type_count']}")
    print(f"    Query fields  : {len(analysis['queries'])}")
    print(f"    Mutation fields: {len(analysis['mutations'])}")

    save_schema(data, analysis)
    print(f"\n[+] Schema saved to {OUTPUT_FILE}")
    print("[+] DVGA discovery complete.")
    sys.exit(0)

if __name__ == "__main__":
    main()
