import re
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

@dataclass
class ParsedLogEntry:
    """Структура для представлення розпарсеного лог-запису"""
    timestamp: datetime
    message: str
    ip_address: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None

class LogParser:
    """Клас для парсингу різних типів лог-файлів"""
    
    def __init__(self):
        # Регулярні вирази для різних форматів дат
        self.date_patterns = [
            # 2024-01-15 14:30:25
            (r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
            # Jan 15 14:30:25
            (r'([A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2})', '%b %d %H:%M:%S'),
            # 15/01/2024 14:30:25
            (r'(\d{1,2}/\d{1,2}/\d{4} \d{2}:\d{2}:\d{2})', '%d/%m/%Y %H:%M:%S'),
            # 2024-01-15T14:30:25
            (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', '%Y-%m-%dT%H:%M:%S'),
            # [15/Jan/2024:14:30:25 +0000] (Apache format)
            (r'\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})', '%d/%b/%Y:%H:%M:%S'),
        ]
        
        # Регулярні вирази для пошуку IP-адрес
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        # Регулярні вирази для пошуку користувачів
        self.username_patterns = [
            r'user[:\s=]+([a-zA-Z0-9_\-]+)',
            r'username[:\s=]+([a-zA-Z0-9_\-]+)',
            r'login[:\s=]+([a-zA-Z0-9_\-]+)',
            r'account[:\s=]+([a-zA-Z0-9_\-]+)',
            r'for user ([a-zA-Z0-9_\-]+)',
            r'by ([a-zA-Z0-9_\-]+)',
        ]
        
        # Паттерни для визначення типів подій
        self.event_patterns = {
            'Login Success': [
                r'login.*success',
                r'authentication.*success',
                r'successful.*login',
                r'user.*logged.*in',
                r'session.*started',
            ],
            'Login Failed': [
                r'login.*fail',
                r'authentication.*fail',
                r'failed.*login',
                r'invalid.*credentials',
                r'access.*denied',
                r'unauthorized.*access',
            ],
            'Port Scan Detected': [
                r'port.*scan',
                r'scan.*detected',
                r'suspicious.*connection',
                r'multiple.*connections',
            ],
            'Malware Alert': [
                r'malware',
                r'virus',
                r'trojan',
                r'backdoor',
                r'ransomware',
                r'threat.*detected',
            ]
        }
    
    def parse_timestamp(self, log_line: str) -> Optional[datetime]:
        """Розпарсити timestamp з лог-рядка"""
        for pattern, format_str in self.date_patterns:
            match = re.search(pattern, log_line, re.IGNORECASE)
            if match:
                try:
                    timestamp_str = match.group(1)
                    # Якщо рік не вказано, додаємо поточний рік
                    if '%Y' not in format_str:
                        current_year = datetime.now().year
                        timestamp_str = f"{current_year} {timestamp_str}"
                        format_str = f"%Y {format_str}"
                    
                    return datetime.strptime(timestamp_str, format_str)
                except ValueError:
                    continue
        return None
    
    def extract_ip_address(self, log_line: str) -> Optional[str]:
        """Витягти IP-адресу з лог-рядка"""
        matches = re.findall(self.ip_pattern, log_line)
        if matches:
            # Повертаємо першу знайдену IP-адресу
            return matches[0]
        return None
    
    def extract_username(self, log_line: str) -> Optional[str]:
        """Витягти ім'я користувача з лог-рядка"""
        for pattern in self.username_patterns:
            match = re.search(pattern, log_line, re.IGNORECASE)
            if match:
                username = match.group(1)
                # Фільтруємо очевидно неправильні значення
                if len(username) > 2 and username not in ['null', 'none', 'empty']:
                    return username
        return None
    
    def detect_event_type(self, log_line: str) -> Tuple[Optional[str], Optional[str]]:
        """Визначити тип події та її серйозність"""
        log_lower = log_line.lower()
        
        for event_type, patterns in self.event_patterns.items():
            for pattern in patterns:
                if re.search(pattern, log_lower):
                    # Визначаємо серйозність на основі типу події
                    severity_map = {
                        'Login Success': 'Informational',
                        'Login Failed': 'Warning',
                        'Port Scan Detected': 'Warning',
                        'Malware Alert': 'Critical'
                    }
                    return event_type, severity_map.get(event_type, 'Informational')
        
        return None, None
    
    def parse_log_line(self, log_line: str) -> Optional[ParsedLogEntry]:
        """Розпарсити один рядок логу"""
        log_line = log_line.strip()
        if not log_line:
            return None
        
        timestamp = self.parse_timestamp(log_line)
        if not timestamp:
            # Якщо не можемо розпарсити timestamp, використовуємо поточний час
            timestamp = datetime.now()
        
        ip_address = self.extract_ip_address(log_line)
        username = self.extract_username(log_line)
        event_type, severity = self.detect_event_type(log_line)
        
        return ParsedLogEntry(
            timestamp=timestamp,
            message=log_line,
            ip_address=ip_address,
            username=username,
            event_type=event_type,
            severity=severity
        )
    
    def parse_log_file(self, file_path: str) -> List[ParsedLogEntry]:
        """Розпарсити весь лог-файл"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Файл {file_path} не знайдено")
        
        parsed_entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                for line_num, line in enumerate(file, 1):
                    try:
                        parsed_entry = self.parse_log_line(line)
                        if parsed_entry:
                            parsed_entries.append(parsed_entry)
                    except Exception as e:
                        print(f"Помилка при парсингу рядка {line_num}: {e}")
                        continue
        except UnicodeDecodeError:
            # Спробуємо з іншим кодуванням
            try:
                with open(file_path, 'r', encoding='cp1251') as file:
                    for line_num, line in enumerate(file, 1):
                        try:
                            parsed_entry = self.parse_log_line(line)
                            if parsed_entry:
                                parsed_entries.append(parsed_entry)
                        except Exception as e:
                            print(f"Помилка при парсингу рядка {line_num}: {e}")
                            continue
            except Exception as e:
                print(f"Не вдалося прочитати файл {file_path}: {e}")
                return []
        
        return parsed_entries
    
    def parse_multiple_log_files(self, file_paths: List[str]) -> List[ParsedLogEntry]:
        """Розпарсити декілька лог-файлів"""
        all_entries = []
        
        for file_path in file_paths:
            print(f"Парсинг файлу: {file_path}")
            try:
                entries = self.parse_log_file(file_path)
                all_entries.extend(entries)
                print(f"Розпарсено {len(entries)} записів з {file_path}")
            except Exception as e:
                print(f"Помилка при парсингу файлу {file_path}: {e}")
        
        # Сортуємо всі записи за часом
        all_entries.sort(key=lambda x: x.timestamp)
        
        return all_entries
    
    def generate_sample_log_file(self, file_path: str, num_entries: int = 100):
        """Генерувати зразковий лог-файл для тестування"""
        import random
        from datetime import timedelta
        
        sample_logs = [
            "2024-01-15 10:30:25 INFO: User admin successfully logged in from 192.168.1.100",
            "2024-01-15 10:31:12 WARN: Failed login attempt for user guest from 192.168.1.200",
            "2024-01-15 10:32:45 WARN: Port scan detected from 203.0.113.1",
            "2024-01-15 10:33:10 CRITICAL: Malware Trojan.Win32.Generic detected on workstation 192.168.1.150",
            "Jan 15 11:15:30 server1 sshd[1234]: Accepted password for admin from 10.0.0.50 port 22 ssh2",
            "Jan 15 11:16:45 server1 sshd[1235]: Failed password for root from 203.0.113.5 port 22 ssh2",
            "[15/Jan/2024:11:20:15 +0000] 192.168.1.75 - user1 \"GET /admin HTTP/1.1\" 200 1234",
            "15/01/2024 11:25:30 ERROR: Authentication failed for username=administrator from IP=192.168.1.201",
            "2024-01-15T11:30:25 WARNING: Suspicious connection attempts from 198.51.100.1",
            "2024-01-15 11:35:40 ALERT: Virus detected: Backdoor.Linux.Mirai on host 192.168.1.88"
        ]
        
        base_time = datetime.now() - timedelta(days=1)
        
        with open(file_path, 'w', encoding='utf-8') as file:
            for i in range(num_entries):
                # Вибираємо випадковий шаблон логу
                template = random.choice(sample_logs)
                
                # Генеруємо новий час
                time_offset = timedelta(minutes=random.randint(0, 1440))  # В межах доби
                new_time = base_time + time_offset
                
                # Замінюємо дату в шаблоні
                if template.startswith('2024-01-15 '):
                    log_entry = template.replace('2024-01-15', new_time.strftime('%Y-%m-%d'))
                    log_entry = log_entry.replace('10:30:25', new_time.strftime('%H:%M:%S'))
                elif template.startswith('Jan 15 '):
                    log_entry = template.replace('Jan 15', new_time.strftime('%b %d'))
                    log_entry = log_entry.replace('11:15:30', new_time.strftime('%H:%M:%S'))
                elif '[15/Jan/2024:' in template:
                    log_entry = template.replace('15/Jan/2024', new_time.strftime('%d/%b/%Y'))
                    log_entry = log_entry.replace('11:20:15', new_time.strftime('%H:%M:%S'))
                elif template.startswith('15/01/2024 '):
                    log_entry = template.replace('15/01/2024', new_time.strftime('%d/%m/%Y'))
                    log_entry = log_entry.replace('11:25:30', new_time.strftime('%H:%M:%S'))
                elif '2024-01-15T' in template:
                    log_entry = template.replace('2024-01-15T11:30:25', new_time.strftime('%Y-%m-%dT%H:%M:%S'))
                else:
                    log_entry = template
                
                # Варіюємо IP-адреси
                ip_variations = ['192.168.1.100', '192.168.1.200', '10.0.0.50', '203.0.113.1', '198.51.100.1']
                for ip in ip_variations:
                    if ip in log_entry:
                        new_ip = f"192.168.1.{random.randint(1, 254)}"
                        log_entry = log_entry.replace(ip, new_ip, 1)
                        break
                
                file.write(log_entry + '\n')
        
        print(f"Згенеровано зразковий лог-файл: {file_path} з {num_entries} записами")