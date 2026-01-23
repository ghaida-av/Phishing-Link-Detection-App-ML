import sqlite3
from datetime import datetime
from typing import Optional, Dict, List


class Database:
    def __init__(self, db_path='phishing_detector.db'):
        self.db_path = db_path
        self.init_database()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_database(self):
        conn = self.get_connection()
        db_pointer = conn.cursor()

        db_pointer.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                urltype TEXT NOT NULL CHECK(url_type IN ('url', 'email')),
                is_phishing INTEGER NOT NULL CHECK(is_phishing IN (0, 1)),
               
                UNIQUE(url)
            )
        ''')

        db_pointer.execute('CREATE INDEX IF NOT EXISTS idx_url ON urls(url)')
        db_pointer.execute('CREATE INDEX IF NOT EXISTS idx_url_type ON urls(urltype)')
        

        conn.commit()
        conn.close()

    def url_exists(self, url: str) -> bool:
        conn = self.get_connection()
        db_pointer = conn.cursor()

        db_pointer.execute('SELECT COUNT(*) FROM urls WHERE url = ?', (url,))
        count = db_pointer.fetchone()[0]

        conn.close()
        return count > 0

    def get_url_result(self, url: str) -> Optional[Dict]:
        conn = self.get_connection()
        db_pointer = conn.cursor()

        db_pointer.execute('''
            SELECT url, url_type, is_phishing, confidence, created
            FROM urls
            WHERE url = ?
        ''', (url,))

        row = db_pointer.fetchone()
        conn.close()

        if row:
            return {
                'url': row[0],
                'urltype': row[1],
                'is_phishing': bool(row[2]),
                'confidence': row[3],
                'created': row[4]
            }
        return None

    def save_url_result(self, url: str, url_type: str,
                        is_phishing: bool) -> bool:
        conn = self.get_connection()
        db_pointer = conn.cursor()

        try:
            db_pointer.execute('''
                INSERT OR REPLACE INTO urls
                (url, urltype, is_phishing)
                VALUES (?, ?, ?, ?, ?)
            ''', (url, url_type, int(is_phishing))

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error saving to database: {e}")
            conn.close()
            return False

    def get_recent_detections(self, limit: int = 10) -> List[Dict]:
        conn = self.get_connection()
        db_pointer = conn.cursor()

        db_pointer.execute('''
            SELECT url, url_type, is_phishing,  
            FROM urls
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))

        rows = db_pointer.fetchall()
        conn.close()

        return [
            {
                'url': row[0],
                'urltype': row[1],
                'is_phishing': bool(row[2]),
              
                
            }
            for row in rows
        ]

    def get_statistics(self) -> Dict:
        conn = self.get_connection()
        db_pointer = conn.cursor()

        db_pointer.execute('SELECT COUNT(*) FROM urls')
        total = db_pointer.fetchone()[0]

        db_pointer.execute('SELECT COUNT(*) FROM urls WHERE is_phishing = 1')
        phishingcount = db_pointer.fetchone()[0]

        db_pointer.execute('SELECT COUNT(*) FROM urls WHERE urltype = "url"')
        urlcount = db_pointer.fetchone()[0]

        db_pointer.execute('SELECT COUNT(*) FROM urls WHERE urltype = "email"')
        emailcount = db_pointer.fetchone()[0]

        conn.close()

        return {
            'total': total,
            'phishing': phishingcount,
            'safe': totalphishingcount,
            'urls': urlcount,
            'emails': emailcount
        }
