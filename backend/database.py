"""
Database module for storing URLs and detection results
"""
import sqlite3
import os
from datetime import datetime
from typing import Optional, Dict, List


class Database:
    def __init__(self, db_path='phishing_detector.db'):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Create URLs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                url_type TEXT NOT NULL CHECK(url_type IN ('url', 'email')),
                is_phishing INTEGER NOT NULL CHECK(is_phishing IN (0, 1)),
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(url)
            )
        ''')
        
        # Create indexes for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_url ON urls(url)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_url_type ON urls(url_type)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_created_at ON urls(created_at)
        ''')
        
        conn.commit()
        conn.close()
    
    def url_exists(self, url: str) -> bool:
        """Check if URL exists in database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM urls WHERE url = ?', (url,))
        count = cursor.fetchone()[0]
        
        conn.close()
        return count > 0
    
    def get_url_result(self, url: str) -> Optional[Dict]:
        """Get stored result for a URL"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT url, url_type, is_phishing, confidence, created_at
            FROM urls
            WHERE url = ?
        ''', (url,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'url': row[0],
                'url_type': row[1],
                'is_phishing': bool(row[2]),
                'confidence': row[3],
                'created_at': row[4]
            }
        return None
    
    def save_url_result(self, url: str, url_type: str, is_phishing: bool, 
                       confidence: float) -> bool:
        """Save URL detection result to database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Use INSERT OR REPLACE to update if exists
            cursor.execute('''
                INSERT OR REPLACE INTO urls (url, url_type, is_phishing, confidence, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (url, url_type, int(is_phishing), confidence, datetime.now()))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error saving to database: {e}")
            conn.close()
            return False
    
    def get_recent_detections(self, limit: int = 10) -> List[Dict]:
        """Get recent detection results"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT url, url_type, is_phishing, confidence, created_at
            FROM urls
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'url': row[0],
                'url_type': row[1],
                'is_phishing': bool(row[2]),
                'confidence': row[3],
                'created_at': row[4]
            }
            for row in rows
        ]
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM urls')
        total = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM urls WHERE is_phishing = 1')
        phishing_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM urls WHERE url_type = "url"')
        url_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM urls WHERE url_type = "email"')
        email_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total': total,
            'phishing': phishing_count,
            'safe': total - phishing_count,
            'urls': url_count,
            'emails': email_count
        }
