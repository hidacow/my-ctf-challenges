#!/usr/bin/env python3
import os
import time
import psycopg2
from psycopg2 import sql


def get_db_connection():
    return psycopg2.connect(
        dbname=os.environ.get("DB_NAME", "docmanager"),
        user=os.environ.get("DB_USER", "docmanager"),
        password=os.environ.get("DB_PASSWORD", "YkhsD4DFgJ04xTXtAJ5Wc4QZ30IlwPeE"),
        host=os.environ.get("DB_HOST", "db"),
        port=os.environ.get("DB_PORT", "5432"),
    )


def wait_for_table(cursor, table_name="minio_credentials"):
    print(f"Waiting for table '{table_name}' to be created by migrations...")
    while True:
        cursor.execute(
            """
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = %s
            );
        """,
            (table_name,),
        )
        if cursor.fetchone()[0]:
            print(f"Table '{table_name}' found!")
            return

        print(f"Table '{table_name}' not found yet. Sleeping 2s...")
        time.sleep(2)


def main():
    print("Starting initial data injection...")

    # Retry connection loop
    conn = None
    while conn is None:
        try:
            conn = get_db_connection()
        except psycopg2.OperationalError as e:
            print(f"Database not ready: {e}")
            time.sleep(2)

    conn.autocommit = True
    cur = conn.cursor()

    try:
        wait_for_table(cur)

        print("Inserting initial MinIO credentials...")

        # Data to insert (matching initial_data.json)
        # document-service (id=1)
        # user-manager (id=2)

        data = [
            (
                1,
                "document-service-admin",
                "document-service",
                "5xOluxCoKRSYByBn3twWHThKUC8SfzmW",
                "",
                True,
                "2025-01-01T00:00:00Z",
            ),
            (
                2,
                "user-manager",
                "user-manager",
                "q6FqTclC0dRbSYw36S95YhvqNeOAWhoV",
                "",
                False,
                "2025-01-01T00:00:00Z",
            ),
        ]

        insert_query = """
            INSERT INTO minio_credentials (id, name, access_key, secret_key, description, is_service_account, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING;
        """

        for row in data:
            cur.execute(insert_query, row)
            print(f"Processed credential: {row[1]}")

        print("Initial data injection completed successfully.")

    except Exception as e:
        print(f"Error during data injection: {e}")
        exit(1)
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
