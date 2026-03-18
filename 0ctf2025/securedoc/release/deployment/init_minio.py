#!/usr/bin/env python3
"""
MinIO Initialization Script for SecureDoc Manager CTF Challenge
Creates a proper hierarchical user structure:
1. document-service (service account under minioadmin, CVE exploitable)
2. user-manager (separate MinIO user with restricted policy)
3. webapp users (service accounts under user-manager user)
"""

import time
import sys
import json
from minio import Minio, MinioAdmin
from minio.credentials.providers import StaticProvider
from minio.error import S3Error
from io import BytesIO

# MinIO configuration
MINIO_ENDPOINT = "minio:9000"
MINIO_ACCESS_KEY = "minioadmin"
MINIO_SECRET_KEY = "7EoSor9oBHYH59Qq5D6FkDn9ACou2O5s"

# Tier 1: Admin service account (SQL injection target, CVE exploitable)
# This is a SERVICE ACCOUNT created under minioadmin
# Players will extract this via SQL injection and exploit CVE-2025-62506
ADMIN_SERVICE_KEY = "document-service"
ADMIN_SERVICE_SECRET = "5xOluxCoKRSYByBn3twWHThKUC8SfzmW"

# Tier 2: User manager (separate MinIO USER with restricted policy)
# This is a real MinIO USER (not service account) with attached policy
# Webapp users are created as service accounts under THIS user
USER_MANAGER_NAME = "user-manager"
USER_MANAGER_PASSWORD = "q6FqTclC0dRbSYw36S95YhvqNeOAWhoV"

# Buckets
BUCKETS = ["documents", "flag-storage"]

# Admin service account policy - restricted to documents bucket only
# This is what players will exploit with CVE-2025-62506 to escalate
ADMIN_SERVICE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:*"],
            "Resource": [
                "arn:aws:s3:::documents",
                "arn:aws:s3:::documents/*"
            ]
        }
    ]
}

# User manager policy - attached to user-manager USER
# Allows S3 operations but CANNOT create service accounts
# Service accounts created under this user inherit restrictions
USER_MANAGER_POLICY_NAME = "user-manager-policy"
USER_MANAGER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:DeleteObject",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::documents",
                "arn:aws:s3:::documents/*"
            ]
        }
    ]
}

def wait_for_minio(client, max_retries=30):
    """Wait for MinIO to be ready"""
    print("Waiting for MinIO to be ready...")
    for i in range(max_retries):
        try:
            client.list_buckets()
            print("✓ MinIO is ready!")
            return True
        except Exception as e:
            if i < max_retries - 1:
                print(f"  Waiting... ({i+1}/{max_retries})")
                time.sleep(2)
            else:
                print(f"✗ MinIO not ready after {max_retries} attempts: {e}")
                return False
    return False

def main():
    print("=" * 60)
    print("MinIO Initialization for SecureDoc Manager")
    print("=" * 60)
    
    # Initialize clients
    client = Minio(
        endpoint=MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False
    )
    
    admin_client = MinioAdmin(
        endpoint=MINIO_ENDPOINT,
        credentials=StaticProvider(
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY
        ),
        secure=False
    )
    
    # Wait for MinIO to be ready
    if not wait_for_minio(client):
        print("✗ Failed to connect to MinIO")
        sys.exit(1)
    
    # Create buckets
    print("\n📦 Creating buckets...")
    for bucket in BUCKETS:
        try:
            if not client.bucket_exists(bucket):
                client.make_bucket(bucket)
                print(f"  ✓ Created bucket: {bucket}")
            else:
                print(f"  ⚠ Bucket already exists: {bucket}")
        except Exception as e:
            print(f"  ✗ Failed to create bucket {bucket}: {e}")
    
    # =========================================================================
    # TIER 1: Create admin service account (under minioadmin)
    # This is the SQL injection target and CVE-2025-62506 exploit point
    # =========================================================================
    print("\n🔐 TIER 1: Creating admin service account (document-service)...")
    print(f"  Parent: minioadmin")
    print(f"  Access Key: {ADMIN_SERVICE_KEY}")
    print(f"  Policy: Restricted to documents bucket only")
    print(f"  Vulnerability: CVE-2025-62506 exploitable")
    print(f"  Storage: Will be saved in database for SQL injection")
    
    try:
        # Delete existing if present
        try:
            admin_client.delete_service_account(ADMIN_SERVICE_KEY)
            print(f"  ✓ Removed existing service account")
        except:
            pass
        
        # Create admin service account from minioadmin with inline policy
        # CVE-2025-62506: This account can create unrestricted child service accounts
        admin_client.add_service_account(
            access_key=ADMIN_SERVICE_KEY,
            secret_key=ADMIN_SERVICE_SECRET,
            policy=ADMIN_SERVICE_POLICY
        )
        print(f"  ✓ Created admin service account: {ADMIN_SERVICE_KEY}")
    except Exception as e:
        print(f"  ✗ Failed to create admin service account: {e}")
        import traceback
        traceback.print_exc()
    
    # Verify admin service account restrictions
    print("\n🧪 Verifying admin service account restrictions...")
    admin_service_client = Minio(
        endpoint=MINIO_ENDPOINT,
        access_key=ADMIN_SERVICE_KEY,
        secret_key=ADMIN_SERVICE_SECRET,
        secure=False
    )
    
    try:
        list(admin_service_client.list_objects("documents", recursive=True))
        print("  ✓ Can access 'documents' bucket")
    except Exception as e:
        print(f"  ✗ Cannot access 'documents' bucket: {e}")
    
    try:
        list(admin_service_client.list_objects("flag-storage", recursive=True))
        print("  ✗ WARNING: Can access 'flag-storage' bucket (should be restricted!)")
    except S3Error as e:
        if "Access Denied" in str(e) or "AccessDenied" in str(e):
            print("  ✓ Cannot access 'flag-storage' bucket (correctly restricted)")
        else:
            print(f"  ? Unexpected error: {e}")
    
    # =========================================================================
    # TIER 2: Create user-manager as a separate MinIO USER (not service account)
    # This is a real user with an attached policy
    # Webapp users will be service accounts created under THIS user
    # =========================================================================
    print("\n👤 TIER 2: Creating user-manager (separate MinIO user)...")
    print(f"  Type: MinIO User (not service account)")
    print(f"  Username: {USER_MANAGER_NAME}")
    print(f"  Policy: Restricted S3 operations only")
    print(f"  Purpose: Parent for all webapp user service accounts")
    print(f"  Protection: Cannot exploit CVE-2025-62506")
    
    try:
        # Step 1: Create the MinIO user first
        print(f"\n  👤 Creating MinIO user: {USER_MANAGER_NAME}")
        try:
            # Try to remove existing user
            admin_client.user_remove(USER_MANAGER_NAME)
            print(f"    ✓ Removed existing user")
        except:
            pass
        
        # Add the user with password
        admin_client.user_add(USER_MANAGER_NAME, USER_MANAGER_PASSWORD)
        print(f"    ✓ Created user: {USER_MANAGER_NAME}")
        
        # Step 2: Create the policy (as a named policy)
        print(f"\n  📋 Creating policy: {USER_MANAGER_POLICY_NAME}")
        try:
            # Try to remove existing policy
            admin_client.policy_remove(USER_MANAGER_POLICY_NAME)
            print(f"    ✓ Removed existing policy")
        except:
            pass
        
        # Write policy to temporary file for policy_add
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(USER_MANAGER_POLICY, f)
            policy_file = f.name
        
        try:
            # Add the policy from file
            admin_client.policy_add(USER_MANAGER_POLICY_NAME, policy_file)
            print(f"    ✓ Created policy: {USER_MANAGER_POLICY_NAME}")
        finally:
            # Clean up temp file
            import os
            os.unlink(policy_file)
        
        # Step 3: Attach policy to user using policy_set
        print(f"\n  🔗 Attaching policy to user...")
        admin_client.policy_set(USER_MANAGER_POLICY_NAME, user=USER_MANAGER_NAME)
        print(f"    ✓ Attached policy {USER_MANAGER_POLICY_NAME} to user {USER_MANAGER_NAME}")
        
        print(f"\n  ✅ User manager setup complete!")
        print(f"    - User: {USER_MANAGER_NAME}")
        print(f"    - Policy: {USER_MANAGER_POLICY_NAME}")
        print(f"    - Webapp will use this user to create per-user service accounts")
        
    except Exception as e:
        print(f"  ✗ Failed to create user manager: {e}")
        import traceback
        traceback.print_exc()
    
    # Verify user-manager can access documents but not flag-storage
    print("\n🧪 Verifying user-manager restrictions...")
    
    # Give MinIO a moment to apply the policy
    time.sleep(2)
    
    user_manager_client = Minio(
        MINIO_ENDPOINT,
        access_key=USER_MANAGER_NAME,
        secret_key=USER_MANAGER_PASSWORD,
        secure=False
    )
    
    try:
        # Try to list objects in documents bucket
        objects = list(user_manager_client.list_objects("documents", recursive=True))
        print(f"  ✓ user-manager can access 'documents' bucket (found {len(objects)} objects)")
    except Exception as e:
        print(f"  ✗ user-manager cannot access 'documents' bucket: {e}")
    
    try:
        list(user_manager_client.list_objects("flag-storage", recursive=True))
        print("  ✗ WARNING: user-manager can access 'flag-storage' bucket (should be restricted!)")
    except S3Error as e:
        if "Access Denied" in str(e) or "AccessDenied" in str(e):
            print("  ✓ user-manager cannot access 'flag-storage' bucket (correctly restricted)")
        else:
            print(f"  ? Unexpected error: {e}")
    
    # Upload flag
    print("\n🚩 Uploading flag...")
    flag_content = "0ops{627fb11e-a8f4-4141-8142-297773ee4b6b}"
    try:
        client.put_object(
            "flag-storage",
            "flag.txt",
            data=BytesIO(flag_content.encode()),
            length=len(flag_content)
        )
        print(f"  ✓ Uploaded flag to flag-storage/flag.txt")
    except Exception as e:
        print(f"  ✗ Failed to upload flag: {e}")
    
    # Upload sample documents
    print("\n📄 Uploading sample documents...")
    samples = [
        ("documents", "welcome.txt", "Welcome! This is a sample document. Flag is not in this bucket btw."),
        ("documents", "readme.txt", "Who are u??? not admin i guess"),
    ]
    
    for bucket, filename, content in samples:
        try:
            client.put_object(
                bucket,
                filename,
                data=BytesIO(content.encode()),
                length=len(content)
            )
            print(f"  ✓ Uploaded {bucket}/{filename}")
        except Exception as e:
            print(f"  ✗ Failed to upload {bucket}/{filename}: {e}")
    
    print("\n" + "=" * 60)
    print("✓ MinIO initialization completed successfully!")
    print("=" * 60)
    print("\n📋 Summary:")
    print(f"  Buckets: {', '.join(BUCKETS)}")
    print(f"\n  TIER 1 - Admin Service Account (SQL injection target):")
    print(f"    Type: Service Account (under minioadmin)")
    print(f"    Access Key: {ADMIN_SERVICE_KEY}")
    print(f"    Policy: documents/* only (inline)")
    print(f"    Vulnerable: YES (CVE-2025-62506)")
    print(f"    Stored in DB: YES")
    print(f"\n  TIER 2 - User Manager (separate MinIO user):")
    print(f"    Type: MinIO User (with attached policy)")
    print(f"    Username: {USER_MANAGER_NAME}")
    print(f"    Password: {USER_MANAGER_PASSWORD}")
    print(f"    Policy: {USER_MANAGER_POLICY_NAME} (S3 operations only)")
    print(f"    Vulnerable: NO (user cannot create unrestricted service accounts)")
    print(f"    Purpose: Parent for webapp user service accounts")
    print(f"    Stored in DB: YES (for webapp to use)")
    print("\n🎯 Challenge Attack Path:")
    print("  1. Register account → Get user service account (created under user-manager)")
    print("  2. User keys are NOT exploitable (parent is a restricted user, not minioadmin)")
    print("  3. SQL injection → Extract document-service credentials")
    print("  4. Use document-service to exploit CVE-2025-62506")
    print("  5. Create unrestricted service account (under minioadmin)")
    print("  6. Access flag-storage bucket → Get flag")
    print("\n🛡️  Security Architecture:")
    print("  minioadmin (root account)")
    print("    ├─ document-service (service account, restricted, CVE exploitable) ← TARGET")
    print("    └─ user-manager (separate user, restricted policy)")
    print("         └─ user-{username}-xxx (service accounts under user-manager)")
    print("             └─ NOT exploitable (parent has no admin permissions)")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✗ Initialization interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Initialization failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
