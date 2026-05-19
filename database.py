import sqlite3
import os
from datetime import datetime

DATABASE_PATH = "codeguard.db"


def init_db():
    """
    Initialize the database.
    Creates the reviews table if it does not exist.
    Called once when the app starts.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            language TEXT NOT NULL,
            security_findings TEXT,
            quality_findings TEXT,
            test_findings TEXT,
            fixed_code TEXT,
            final_report TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("[Database] Initialized successfully.")


def save_review(state: dict):
    """
    Save a completed review to the database.
    Called after all agents have finished running.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO reviews (
            timestamp,
            language,
            security_findings,
            quality_findings,
            test_findings,
            fixed_code,
            final_report
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        state.get("language", "Unknown"),
        state.get("security_findings", ""),
        state.get("quality_findings", ""),
        state.get("test_findings", ""),
        state.get("fixed_code", ""),
        state.get("final_report", "")
    ))

    conn.commit()
    conn.close()
    print("[Database] Review saved.")


def get_all_reviews():
    """
    Retrieve all past reviews from the database.
    Returns id, timestamp, language and final report for each review.
    Used to display review history in the UI.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, timestamp, language, final_report
        FROM reviews
        ORDER BY timestamp DESC
    """)

    reviews = cursor.fetchall()
    conn.close()
    return reviews


def get_review_by_id(review_id: int):
    """
    Retrieve a specific review by its ID.
    Used when user clicks on a past review in history.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM reviews WHERE id = ?
    """, (review_id,))

    review = cursor.fetchone()
    conn.close()
    return review


def delete_review(review_id: int):
    """
    Delete a specific review by its ID.
    Used when user wants to clear a past review.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM reviews WHERE id = ?
    """, (review_id,))

    conn.commit()
    conn.close()
    print(f"[Database] Review {review_id} deleted.")