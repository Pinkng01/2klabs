import sqlite3
import os
from datetime import datetime, timedelta
from typing import List, Tuple, Optional, Dict, Any

class SecurityEventsDB:
    """Клас для роботи з базою даних подій безпеки"""
    
    def __init__(self, db_path: str = "security_events.db"):
        self.db_path = db_path
        self.init_database()
        self.populate_initial_data()
    
    def get_connection(self) -> sqlite3.Connection:
        """Отримати з'єднання з базою даних"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Дозволяє доступ до колонок за іменем
        return conn
    
    def init_database(self):
        """Ініціалізація бази даних та створення таблиць"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Створення таблиці EventSources
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS EventSources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                location TEXT NOT NULL,
                type TEXT NOT NULL
            )
        ''')
        
        # Створення таблиці EventTypes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS EventTypes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type_name TEXT UNIQUE NOT NULL,
                severity TEXT NOT NULL
            )
        ''')
        
        # Створення таблиці SecurityEvents
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS SecurityEvents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                source_id INTEGER NOT NULL,
                event_type_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                ip_address TEXT,
                username TEXT,
                FOREIGN KEY (source_id) REFERENCES EventSources (id),
                FOREIGN KEY (event_type_id) REFERENCES EventTypes (id)
            )
        ''')
        
        # Створення індексів для оптимізації запитів
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON SecurityEvents(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_address ON SecurityEvents(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON SecurityEvents(username)')
        
        conn.commit()
        conn.close()
    
    def populate_initial_data(self):
        """Заповнення початковими даними"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Перевіряємо, чи є дані в EventTypes
        cursor.execute("SELECT COUNT(*) FROM EventTypes")
        if cursor.fetchone()[0] == 0:
            # Вставка початкових типів подій
            event_types = [
                ("Login Success", "Informational"),
                ("Login Failed", "Warning"),
                ("Port Scan Detected", "Warning"),
                ("Malware Alert", "Critical")
            ]
            
            cursor.executemany('''
                INSERT INTO EventTypes (type_name, severity) VALUES (?, ?)
            ''', event_types)
        
        # Перевіряємо, чи є дані в EventSources
        cursor.execute("SELECT COUNT(*) FROM EventSources")
        if cursor.fetchone()[0] == 0:
            # Вставка тестових джерел подій
            event_sources = [
                ("Firewall_A", "192.168.1.1", "Firewall"),
                ("Web_Server_Logs", "192.168.1.10", "Web Server"),
                ("IDS_Sensor_B", "192.168.1.20", "IDS"),
                ("Domain_Controller", "192.168.1.5", "Active Directory"),
                ("Mail_Server", "192.168.1.15", "Email Server")
            ]
            
            cursor.executemany('''
                INSERT INTO EventSources (name, location, type) VALUES (?, ?, ?)
            ''', event_sources)
        
        # Перевіряємо, чи є дані в SecurityEvents
        cursor.execute("SELECT COUNT(*) FROM SecurityEvents")
        if cursor.fetchone()[0] == 0:
            self._insert_test_events(cursor)
        
        conn.commit()
        conn.close()
    
    def _insert_test_events(self, cursor):
        """Вставка тестових подій безпеки"""
        from datetime import datetime, timedelta
        import random
        
        # Отримуємо ID джерел та типів подій
        cursor.execute("SELECT id FROM EventSources")
        source_ids = [row[0] for row in cursor.fetchall()]
        
        cursor.execute("SELECT id FROM EventTypes")
        event_type_ids = [row[0] for row in cursor.fetchall()]
        
        # Генеруємо тестові події
        test_events = []
        base_time = datetime.now()
        
        # Генеруємо події за останні 7 днів
        for i in range(50):
            timestamp = base_time - timedelta(
                days=random.randint(0, 7),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            source_id = random.choice(source_ids)
            event_type_id = random.choice(event_type_ids)
            
            # Різні типи повідомлень залежно від типу події
            if event_type_id == 1:  # Login Success
                message = f"User successfully logged in from IP {random.choice(['192.168.1.100', '10.0.0.50', '172.16.0.25'])}"
                ip_address = random.choice(['192.168.1.100', '10.0.0.50', '172.16.0.25'])
                username = random.choice(['admin', 'user1', 'manager', 'operator'])
            elif event_type_id == 2:  # Login Failed
                message = f"Failed login attempt from IP {random.choice(['192.168.1.200', '10.0.0.100', '172.16.0.50'])}"
                ip_address = random.choice(['192.168.1.200', '10.0.0.100', '172.16.0.50', '203.0.113.1'])
                username = random.choice(['admin', 'root', 'administrator', 'guest', None])
            elif event_type_id == 3:  # Port Scan Detected
                message = f"Port scan detected from IP {random.choice(['203.0.113.1', '198.51.100.1', '192.0.2.1'])}"
                ip_address = random.choice(['203.0.113.1', '198.51.100.1', '192.0.2.1'])
                username = None
            else:  # Malware Alert
                message = f"Malware detected: {random.choice(['Trojan.Win32.Generic', 'Backdoor.Linux.Mirai', 'Ransomware.WannaCry'])}"
                ip_address = random.choice(['192.168.1.150', '10.0.0.75', None])
                username = random.choice(['user2', 'workstation1', None])
            
            test_events.append((
                timestamp.isoformat(),
                source_id,
                event_type_id,
                message,
                ip_address,
                username
            ))
        
        cursor.executemany('''
            INSERT INTO SecurityEvents (timestamp, source_id, event_type_id, message, ip_address, username)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', test_events)
    
    def register_event_source(self, name: str, location: str, source_type: str) -> int:
        """Реєстрація нового джерела подій"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO EventSources (name, location, type) VALUES (?, ?, ?)
            ''', (name, location, source_type))
            
            source_id = cursor.lastrowid
            conn.commit()
            return source_id
            
        except sqlite3.IntegrityError:
            raise ValueError(f"Джерело з назвою '{name}' вже існує")
        finally:
            conn.close()
    
    def register_event_type(self, type_name: str, severity: str) -> int:
        """Реєстрація нового типу подій"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO EventTypes (type_name, severity) VALUES (?, ?)
            ''', (type_name, severity))
            
            type_id = cursor.lastrowid
            conn.commit()
            return type_id
            
        except sqlite3.IntegrityError:
            raise ValueError(f"Тип події '{type_name}' вже існує")
        finally:
            conn.close()
    
    def log_security_event(self, source_id: int, event_type_id: int, message: str, 
                          ip_address: Optional[str] = None, username: Optional[str] = None,
                          timestamp: Optional[datetime] = None) -> int:
        """Запис нової події безпеки"""
        if timestamp is None:
            timestamp = datetime.now()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO SecurityEvents (timestamp, source_id, event_type_id, message, ip_address, username)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp.isoformat(), source_id, event_type_id, message, ip_address, username))
            
            event_id = cursor.lastrowid
            conn.commit()
            return event_id
            
        finally:
            conn.close()
    
    def get_failed_logins_24h(self) -> List[Dict[str, Any]]:
        """Отримати всі події 'Login Failed' за останні 24 години"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
        
        cursor.execute('''
            SELECT se.*, es.name as source_name, et.type_name, et.severity
            FROM SecurityEvents se
            JOIN EventSources es ON se.source_id = es.id
            JOIN EventTypes et ON se.event_type_id = et.id
            WHERE et.type_name = 'Login Failed' 
            AND se.timestamp >= ?
            ORDER BY se.timestamp DESC
        ''', (twenty_four_hours_ago.isoformat(),))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def detect_brute_force_attacks(self) -> List[Dict[str, Any]]:
        """Виявити IP-адреси з більше ніж 5 невдалих спроб входу за 1 годину"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        one_hour_ago = datetime.now() - timedelta(hours=1)
        
        cursor.execute('''
            SELECT ip_address, COUNT(*) as failed_attempts,
                   MIN(timestamp) as first_attempt,
                   MAX(timestamp) as last_attempt
            FROM SecurityEvents se
            JOIN EventTypes et ON se.event_type_id = et.id
            WHERE et.type_name = 'Login Failed'
            AND se.timestamp >= ?
            AND se.ip_address IS NOT NULL
            GROUP BY ip_address
            HAVING COUNT(*) > 5
            ORDER BY failed_attempts DESC
        ''', (one_hour_ago.isoformat(),))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def get_critical_events_week(self) -> List[Dict[str, Any]]:
        """Отримати всі критичні події за останній тиждень, згруповані за джерелом"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        one_week_ago = datetime.now() - timedelta(weeks=1)
        
        cursor.execute('''
            SELECT es.name as source_name, es.location, es.type as source_type,
                   COUNT(*) as critical_events_count,
                   GROUP_CONCAT(se.message, '; ') as messages
            FROM SecurityEvents se
            JOIN EventSources es ON se.source_id = es.id
            JOIN EventTypes et ON se.event_type_id = et.id
            WHERE et.severity = 'Critical'
            AND se.timestamp >= ?
            GROUP BY es.id, es.name, es.location, es.type
            ORDER BY critical_events_count DESC
        ''', (one_week_ago.isoformat(),))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def search_events_by_keyword(self, keyword: str) -> List[Dict[str, Any]]:
        """Знайти всі події, що містять певне ключове слово у повідомленні"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT se.*, es.name as source_name, et.type_name, et.severity
            FROM SecurityEvents se
            JOIN EventSources es ON se.source_id = es.id
            JOIN EventTypes et ON se.event_type_id = et.id
            WHERE se.message LIKE ?
            ORDER BY se.timestamp DESC
        ''', (f'%{keyword}%',))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def get_event_sources(self) -> List[Dict[str, Any]]:
        """Отримати всі джерела подій"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM EventSources ORDER BY name')
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def get_event_types(self) -> List[Dict[str, Any]]:
        """Отримати всі типи подій"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM EventTypes ORDER BY type_name')
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results