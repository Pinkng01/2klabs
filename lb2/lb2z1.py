
"""
    Напишіть функцію analyze_log_file(log_file_path), яка приймає шлях до файлу журналу http-сервера (текстового файлу). Функція повинна:
    Прочитати кожний рядок файлу. Типовий лог-файл “apache_logs.txt” додається
    Визначити кількість входжень унікальний кодів відповідей http-сервера (наприклад, 200, 404, 500 і т.д.).
    Зберегти результати у словнику, де ключем є код відповіді, а значенням - кількість його входжень.
    Обробити можливі винятки, такі як відсутність файлу (FileNotFoundError) або помилки читання файлу (IOError), виводячи інформативне повідомлення про помилку.
    Повернути отриманий словник з результатами аналізу.

"""
import sys

def analyze_log_file(log_file_path):
    response_codes = {}
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                try:
                    parts = line.split()
                    if len(parts) >= 9: 
                        code = parts[8]  # HTTP status code is usually the 9th field
                        if code.isdigit():  # Verify it's a numeric status code
                            response_codes[code] = response_codes.get(code, 0) + 1
                except (IndexError, ValueError) as e:
                    # Skip lines that don't match expected format
                    continue
    
    except FileNotFoundError:
        print(f"Error: The file '{log_file_path}' was not found.")
        return {}
    except IOError:
        print(f"Error reading file '{log_file_path}': {IOError}")
        return {}
    
    return response_codes


if __name__ == "__main__":

    # Check if a file path was provided as an argument

    if len(sys.argv) < 2:
        print("Usage: python lb3z1.py <path_to_log_file>")
        print("Example: python lb3z1.py apache_logs.txt")
        sys.exit(1)
    
    log_file = sys.argv[1]
    result = analyze_log_file(log_file)
    
    print("\nHTTP Response Code Analysis:")
    print("============================")
    for code, count in sorted(result.items()):
        print(f"Code {code}: {count} occurrences")
    print("============================")
    print(f"Total unique status codes: {len(result)}")
