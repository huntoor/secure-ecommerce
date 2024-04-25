import sqlite3
import hashlib
from config import DATABASE_URL

def create_connection():
    return sqlite3.connect(DATABASE_URL)

def create_user_table(conn):
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS User (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
    )
    ''')
    conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
