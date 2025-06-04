
"""
Система управління подіями безпеки
Головна програма для запуску системи
"""

import sys
import os
from datetime import datetime
from sec_manager import SecurityEventsManager

def main():
    """Головна функція програми"""
    print("🛡️  Ініціалізація системи управління подіями безпеки...")
    
    try:
        # Створюємо менеджер подій безпеки
        manager = SecurityEventsManager()
        
        print("✅ Система успішно ініціалізована!")
        print(f"📅 Поточна дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Показуємо початкову статистику
        stats = manager.get_statistics()
        print(f"📊 Початкова статистика:")
        print(f"   • Джерел подій: {stats['total_sources']}")
        print(f"   • Типів подій: {stats['total_event_types']}")
        print(f"   • Всього подій в системі: {stats['total_events']}")
        
        # Перевіряємо аргументи командного рядка
        if len(sys.argv) > 1:
            handle_command_line_args(manager, sys.argv[1:])
        else:
            # Запускаємо інтерактивне меню
            manager.interactive_menu()
            
    except KeyboardInterrupt:
        print("\n👋 Програма перервана користувачем")
    except Exception as e:
        print(f"❌ Критична помилка: {e}")
        sys.exit(1)

def handle_command_line_args(manager: SecurityEventsManager, args: list):
    """Обробка аргументів командного рядка"""
    
    if args[0] == '--help' or args[0] == '-h':
        print_help()
        return
    
    elif args[0] == '--stats':
        # Показати статистику
        stats = manager.get_statistics()
        manager._show_statistics()
    
    elif args[0] == '--import' and len(args) >= 3:
        # Імпорт логів: --import <file_path> <source_name>
        file_path = args[1]
        source_name = args[2]
        
        if not os.path.exists(file_path):
            print(f"❌ Файл {file_path} не існує")
            return
        
        print(f"📁 Імпорт логів з файлу {file_path} для джерела {source_name}")
        imported = manager.import_logs_from_file(file_path, source_name)
        print(f"✅ Імпортовано {imported} записів")
    
    elif args[0] == '--failed-logins':
        # Показати невдалі входи за 24 години
        results = manager.get_failed_logins_24h()
        manager.print_results_table(results, "Невдалі входи за 24 години")
    
    elif args[0] == '--brute-force':
        # Виявити атаки підбору пароля
        results = manager.detect_brute_force_attacks()
        manager.print_results_table(results, "Потенційні атаки підбору пароля")
    
    elif args[0] == '--critical':
        # Показати критичні події за тиждень
        results = manager.get_critical_events_week()
        manager.print_results_table(results, "Критичні події за тиждень")
    
    elif args[0] == '--search' and len(args) >= 2:
        # Пошук за ключовим словом: --search <keyword>
        keyword = args[1]
        results = manager.search_events_by_keyword(keyword)
        manager.print_results_table(results, f"Пошук за '{keyword}'")
    
    elif args[0] == '--generate-logs':
        # Згенерувати зразкові логи
        file_path = args[1] if len(args) >= 2 else "sample_logs.txt"
        num_entries = int(args[2]) if len(args) >= 3 and args[2].isdigit() else 100
        
        generated_file = manager.generate_sample_logs(file_path, num_entries)
        print(f"✅ Згенеровано зразкові логи: {generated_file}")
    
    elif args[0] == '--add-source' and len(args) >= 4:
        # Додати джерело: --add-source <name> <location> <type>
        name, location, source_type = args[1], args[2], args[3]
        try:
            source_id = manager.register_event_source(name, location, source_type)
            print(f"✅ Джерело '{name}' додано з ID: {source_id}")
        except ValueError as e:
            print(f"❌ Помилка: {e}")
    
    elif args[0] == '--add-event-type' and len(args) >= 3:
        # Додати тип події: --add-event-type <type_name> <severity>
        type_name, severity = args[1], args[2]
        try:
            type_id = manager.register_event_type(type_name, severity)
            print(f"✅ Тип події '{type_name}' додано з ID: {type_id}")
        except ValueError as e:
            print(f"❌ Помилка: {e}")
    
    else:
        print(f"❌ Невідома команда: {args[0]}")
        print("Використовуйте --help для допомоги")

def print_help():
    """Вивести довідку"""
    help_text = """
🛡️  СИСТЕМА УПРАВЛІННЯ ПОДІЯМИ БЕЗПЕКИ

ВИКОРИСТАННЯ:
    python main.py [ОПЦІЇ]

ОПЦІЇ:
    --help, -h                    Показати цю довідку
    --stats                       Показати статистику системи
    --import <файл> <джерело>     Імпортувати логи з файлу
    --failed-logins              Показати невдалі входи за 24 години
    --brute-force                Виявити атаки підбору пароля
    --critical                   Показати критичні події за тиждень
    --search <ключове_слово>     Пошук подій за ключовим словом
    --generate-logs [файл] [к-сть] Згенерувати зразкові логи
    --add-source <назва> <місце> <тип> Додати нове джерело подій
    --add-event-type <назва> <серйозність> Додати новий тип події

ПРИКЛАДИ:
    python main.py                           # Інтерактивне меню
    python main.py --stats                   # Показати статистику
    python main.py --import logs.txt Firewall_A  # Імпорт логів
    python main.py --search "malware"        # Пошук за словом "malware"
    python main.py --generate-logs sample.txt 50  # Згенерувати 50 записів

Без аргументів запускається інтерактивне меню.
"""
    print(help_text)

def demo_mode():
    """Демонстраційний режим з прикладами використання"""
    print("🎯 ДЕМОНСТРАЦІЙНИЙ РЕЖИМ")
    print("="*50)
    
    manager = SecurityEventsManager()
    
    # Генеруємо зразкові логи
    print("\n1️⃣ Генерація зразкових логів...")
    sample_file = manager.generate_sample_logs("demo_logs.txt", 20)
    
    # Імпортуємо логи
    print("\n2️⃣ Імпорт згенерованих логів...")
    imported = manager.import_logs_from_file(sample_file, "Firewall_A")
    
    # Показуємо різні типи запитів
    print("\n3️⃣ Аналіз невдалих входів за 24 години...")
    failed_logins = manager.get_failed_logins_24h()
    manager.print_results_table(failed_logins[:3], "Приклад невдалих входів")
    
    print("\n4️⃣ Пошук подій з словом 'login'...")
    search_results = manager.search_events_by_keyword("login")
    manager.print_results_table(search_results[:3], "Приклад пошуку")
    
    print("\n5️⃣ Виявлення потенційних атак...")
    brute_force = manager.detect_brute_force_attacks()
    if brute_force:
        manager.print_results_table(brute_force, "Підозрілі IP-адреси")
    else:
        print("🛡️ Підозрілих активностей не виявлено")
    
    print("\n✅ Демонстрація завершена!")
    print(f"📄 Згенеровано файл: {sample_file}")
    print("🗃️ База даних: security_events.db")

if __name__ == "__main__":
    # Перевіряємо, чи потрібно запустити демо
    if len(sys.argv) > 1 and sys.argv[1] == '--demo':
        demo_mode()
    else:
        main()