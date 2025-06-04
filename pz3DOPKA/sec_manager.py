from typing import List, Dict, Any, Optional
from datetime import datetime
from database import SecurityEventsDB
from log_parser import LogParser, ParsedLogEntry

class SecurityEventsManager:
    """Основний клас для управління подіями безпеки"""
    
    def __init__(self, db_path: str = "security_events.db"):
        self.db = SecurityEventsDB(db_path)
        self.parser = LogParser()
    
    def register_event_source(self, name: str, location: str, source_type: str) -> int:
        """Реєстрація нового джерела подій"""
        try:
            source_id = self.db.register_event_source(name, location, source_type)
            print(f"✅ Джерело подій '{name}' успішно зареєстровано з ID: {source_id}")
            return source_id
        except ValueError as e:
            print(f"❌ Помилка реєстрації джерела: {e}")
            raise
    
    def register_event_type(self, type_name: str, severity: str) -> int:
        """Реєстрація нового типу подій"""
        valid_severities = ['Informational', 'Warning', 'Critical']
        if severity not in valid_severities:
            raise ValueError(f"Серйозність має бути одна з: {', '.join(valid_severities)}")
        
        try:
            type_id = self.db.register_event_type(type_name, severity)
            print(f"✅ Тип події '{type_name}' успішно зареєстровано з ID: {type_id}")
            return type_id
        except ValueError as e:
            print(f"❌ Помилка реєстрації типу події: {e}")
            raise
    
    def log_security_event(self, source_id: int, event_type_id: int, message: str,
                          ip_address: Optional[str] = None, username: Optional[str] = None,
                          timestamp: Optional[datetime] = None) -> int:
        """Запис нової події безпеки"""
        try:
            event_id = self.db.log_security_event(
                source_id, event_type_id, message, ip_address, username, timestamp
            )
            print(f"✅ Подія безпеки записана з ID: {event_id}")
            return event_id
        except Exception as e:
            print(f"❌ Помилка запису події: {e}")
            raise
    
    def import_logs_from_file(self, file_path: str, source_name: str) -> int:
        """Імпорт логів з файлу"""
        print(f"🔄 Початок імпорту логів з файлу: {file_path}")
        
        # Знаходимо джерело подій за назвою
        sources = self.db.get_event_sources()
        source = next((s for s in sources if s['name'] == source_name), None)
        
        if not source:
            print(f"❌ Джерело '{source_name}' не знайдено")
            return 0
        
        source_id = source['id']
        
        # Отримуємо всі типи подій для швидкого пошуку
        event_types = {et['type_name']: et for et in self.db.get_event_types()}
        
        # Парсимо файл
        try:
            parsed_entries = self.parser.parse_log_file(file_path)
            imported_count = 0
            
            for entry in parsed_entries:
                try:
                    # Визначаємо тип події
                    if entry.event_type and entry.event_type in event_types:
                        event_type_id = event_types[entry.event_type]['id']
                    else:
                        # Якщо тип не визначено, використовуємо загальний тип
                        event_type_id = event_types.get('Login Success', {}).get('id', 1)
                    
                    # Записуємо подію в БД
                    self.db.log_security_event(
                        source_id=source_id,
                        event_type_id=event_type_id,
                        message=entry.message,
                        ip_address=entry.ip_address,
                        username=entry.username,
                        timestamp=entry.timestamp
                    )
                    imported_count += 1
                    
                except Exception as e:
                    print(f"⚠️ Помилка імпорту запису: {e}")
                    continue
            
            print(f"✅ Успішно імпортовано {imported_count} записів з {len(parsed_entries)} розпарсених")
            return imported_count
            
        except Exception as e:
            print(f"❌ Помилка імпорту файлу: {e}")
            return 0
    
    def import_logs_from_multiple_files(self, file_paths: List[str], source_name: str) -> int:
        """Імпорт логів з декількох файлів"""
        total_imported = 0
        
        for file_path in file_paths:
            imported = self.import_logs_from_file(file_path, source_name)
            total_imported += imported
        
        print(f"🎯 Загалом імпортовано {total_imported} записів з {len(file_paths)} файлів")
        return total_imported
    
    def get_failed_logins_24h(self) -> List[Dict[str, Any]]:
        """Отримати всі події 'Login Failed' за останні 24 години"""
        results = self.db.get_failed_logins_24h()
        print(f"🔍 Знайдено {len(results)} невдалих спроб входу за останні 24 години")
        return results
    
    def detect_brute_force_attacks(self) -> List[Dict[str, Any]]:
        """Виявити потенційні атаки підбору пароля"""
        results = self.db.detect_brute_force_attacks()
        print(f"🚨 Виявлено {len(results)} підозрілих IP-адрес з множинними невдалими спробами входу")
        return results
    
    def get_critical_events_week(self) -> List[Dict[str, Any]]:
        """Отримати критичні події за тиждень, згруповані за джерелом"""
        results = self.db.get_critical_events_week()
        print(f"⚠️ Знайдено критичні події з {len(results)} джерел за останній тиждень")
        return results
    
    def search_events_by_keyword(self, keyword: str) -> List[Dict[str, Any]]:
        """Пошук подій за ключовим словом"""
        results = self.db.search_events_by_keyword(keyword)
        print(f"🔎 Знайдено {len(results)} подій з ключовим словом '{keyword}'")
        return results
    
    def get_event_sources(self) -> List[Dict[str, Any]]:
        """Отримати всі джерела подій"""
        return self.db.get_event_sources()
    
    def get_event_types(self) -> List[Dict[str, Any]]:
        """Отримати всі типи подій"""
        return self.db.get_event_types()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Отримати статистику системи"""
        sources = self.get_event_sources()
        event_types = self.get_event_types()
        
        # Get recent events count
        from datetime import timedelta
        recent_events = self.search_events_by_keyword("")  # Get all events
        
        stats = {
            'total_sources': len(sources),
            'total_event_types': len(event_types),
            'total_events': len(recent_events),
            'sources': sources,
            'event_types': event_types
        }
        
        return stats
    
    def generate_sample_logs(self, file_path: str = "sample_logs.txt", num_entries: int = 100):
        """Генерувати зразкові логи для тестування"""
        self.parser.generate_sample_log_file(file_path, num_entries)
        return file_path
    
    def print_results_table(self, results: List[Dict[str, Any]], title: str = "Результати"):
        """Вивести результати у вигляді таблиці"""
        if not results:
            print(f"\n📋 {title}: Дані не знайдено")
            return
        
        print(f"\n📋 {title} ({len(results)} записів):")
        print("=" * 80)
        
        # Визначаємо, які поля показувати
        if 'timestamp' in results[0]:
            for i, result in enumerate(results[:10], 1):  # Показуємо перші 10 записів
                print(f"{i}. {result.get('timestamp', 'N/A')} | "
                      f"Джерело: {result.get('source_name', 'N/A')} | "
                      f"Тип: {result.get('type_name', 'N/A')} | "
                      f"IP: {result.get('ip_address', 'N/A')} | "
                      f"Користувач: {result.get('username', 'N/A')}")
                print(f"   Повідомлення: {result.get('message', 'N/A')[:100]}...")
                print("-" * 80)
        else:
            # Для інших типів результатів
            for i, result in enumerate(results, 1):
                print(f"{i}. {result}")
                print("-" * 80)
        
        if len(results) > 10:
            print(f"... та ще {len(results) - 10} записів")
    
    def interactive_menu(self):
        """Інтерактивне меню для роботи з системою"""
        while True:
            print("\n" + "="*60)
            print("🛡️  СИСТЕМА УПРАВЛІННЯ ПОДІЯМИ БЕЗПЕКИ")
            print("="*60)
            print("1. 📊 Переглянути статистику системи")
            print("2. 📝 Зареєструвати нове джерело подій")
            print("3. 🏷️  Зареєструвати новий тип подій")
            print("4. ✍️  Записати нову подію безпеки")
            print("5. 📁 Імпортувати логи з файлу")
            print("6. 🔍 Невдалі входи за 24 години")
            print("7. 🚨 Виявити атаки підбору пароля")
            print("8. ⚠️  Критичні події за тиждень")
            print("9. 🔎 Пошук за ключовим словом")
            print("10. 📄 Згенерувати зразкові логи")
            print("0. 🚪 Вийти")
            print("="*60)
            
            choice = input("Виберіть опцію (0-10): ").strip()
            
            try:
                if choice == '0':
                    print("👋 До побачення!")
                    break
                elif choice == '1':
                    self._show_statistics()
                elif choice == '2':
                    self._register_source_interactive()
                elif choice == '3':
                    self._register_event_type_interactive()
                elif choice == '4':
                    self._log_event_interactive()
                elif choice == '5':
                    self._import_logs_interactive()
                elif choice == '6':
                    results = self.get_failed_logins_24h()
                    self.print_results_table(results, "Невдалі входи за 24 години")
                elif choice == '7':
                    results = self.detect_brute_force_attacks()
                    self.print_results_table(results, "Підозрілі IP-адреси")
                elif choice == '8':
                    results = self.get_critical_events_week()
                    self.print_results_table(results, "Критичні події за тиждень")
                elif choice == '9':
                    keyword = input("Введіть ключове слово для пошуку: ").strip()
                    if keyword:
                        results = self.search_events_by_keyword(keyword)
                        self.print_results_table(results, f"Пошук за '{keyword}'")
                elif choice == '10':
                    file_path = input("Шлях до файлу (натисніть Enter для 'sample_logs.txt'): ").strip()
                    if not file_path:
                        file_path = "sample_logs.txt"
                    num_entries = input("Кількість записів (натисніть Enter для 100): ").strip()
                    num_entries = int(num_entries) if num_entries.isdigit() else 100
                    self.generate_sample_logs(file_path, num_entries)
                else:
                    print("❌ Невірний вибір. Спробуйте знову.")
                    
            except KeyboardInterrupt:
                print("\n👋 До побачення!")
                break
            except Exception as e:
                print(f"❌ Помилка: {e}")
    
    def _show_statistics(self):
        """Показати статистику системи"""
        stats = self.get_statistics()
        print(f"\n📊 СТАТИСТИКА СИСТЕМИ:")
        print(f"📍 Джерел подій: {stats['total_sources']}")
        print(f"🏷️  Типів подій: {stats['total_event_types']}")
        print(f"📝 Всього подій: {stats['total_events']}")
        
        print(f"\n📍 ДЖЕРЕЛА ПОДІЙ:")
        for source in stats['sources']:
            print(f"  • {source['name']} ({source['type']}) - {source['location']}")
        
        print(f"\n🏷️  ТИПИ ПОДІЙ:")
        for event_type in stats['event_types']:
            print(f"  • {event_type['type_name']} [{event_type['severity']}]")
    
    def _register_source_interactive(self):
        """Інтерактивна реєстрація джерела"""
        print("\n📝 РЕЄСТРАЦІЯ НОВОГО ДЖЕРЕЛА ПОДІЙ:")
        name = input("Назва джерела: ").strip()
        location = input("Місце розташування/IP: ").strip()
        source_type = input("Тип джерела: ").strip()
        
        if name and location and source_type:
            self.register_event_source(name, location, source_type)
        else:
            print("❌ Всі поля є обов'язковими")
    
    def _register_event_type_interactive(self):
        """Інтерактивна реєстрація типу події"""
        print("\n🏷️  РЕЄСТРАЦІЯ НОВОГО ТИПУ ПОДІЙ:")
        type_name = input("Назва типу події: ").strip()
        print("Доступні рівні серйозності: Informational, Warning, Critical")
        severity = input("Серйозність: ").strip()
        
        if type_name and severity:
            self.register_event_type(type_name, severity)
        else:
            print("❌ Всі поля є обов'язковими")
    
    def _log_event_interactive(self):
        """Інтерактивний запис події"""
        print("\n✍️  ЗАПИС НОВОЇ ПОДІЇ БЕЗПЕКИ:")
        
        # Показуємо доступні джерела
        sources = self.get_event_sources()
        print("Доступні джерела:")
        for i, source in enumerate(sources, 1):
            print(f"  {i}. {source['name']} ({source['type']})")
        
        source_idx = input("Номер джерела: ").strip()
        if not source_idx.isdigit() or int(source_idx) < 1 or int(source_idx) > len(sources):
            print("❌ Невірний номер джерела")
            return
        
        source_id = sources[int(source_idx) - 1]['id']
        
        # Показуємо доступні типи подій
        event_types = self.get_event_types()
        print("\nДоступні типи подій:")
        for i, event_type in enumerate(event_types, 1):
            print(f"  {i}. {event_type['type_name']} [{event_type['severity']}]")
        
        type_idx = input("Номер типу події: ").strip()
        if not type_idx.isdigit() or int(type_idx) < 1 or int(type_idx) > len(event_types):
            print("❌ Невірний номер типу події")
            return
        
        event_type_id = event_types[int(type_idx) - 1]['id']
        
        message = input("Повідомлення: ").strip()
        ip_address = input("IP-адреса (опціонально): ").strip() or None
        username = input("Ім'я користувача (опціонально): ").strip() or None
        
        if message:
            self.log_security_event(source_id, event_type_id, message, ip_address, username)
        else:
            print("❌ Повідомлення є обов'язковим")
    
    def _import_logs_interactive(self):
        """Інтерактивний імпорт логів"""
        print("\n📁 ІМПОРТ ЛОГІВ З ФАЙЛУ:")
        
        # Показуємо доступні джерела
        sources = self.get_event_sources()
        print("Доступні джерела:")
        for i, source in enumerate(sources, 1):
            print(f"  {i}. {source['name']} ({source['type']})")
        
        source_idx = input("Номер джерела: ").strip()
        if not source_idx.isdigit() or int(source_idx) < 1 or int(source_idx) > len(sources):
            print("❌ Невірний номер джерела")
            return
        
        source_name = sources[int(source_idx) - 1]['name']
        
        file_path = input("Шлях до лог-файлу: ").strip()
        if file_path:
            self.import_logs_from_file(file_path, source_name)
        else:
            print("❌ Шлях до файлу є обов'язковим")