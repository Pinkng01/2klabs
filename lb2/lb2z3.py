"""
Завдання 3: Фільтрація IP-адрес з файлу
Напишіть функцію filter_ips(input_file_path, output_file_path, allowed_ips), яка аналізує IP-адреси з лог-файла http-сервера:
Читає IP-адреси з кожного рядка файлу input_file_path. 
Перевіряє, чи кожна прочитана IP-адреса присутня у списку дозволених IP-адрес allowed_ips. Попередньо необхідно задати список (масив) дозволених IP-адрес allowed_ips.
Рахує скільки разів зустрічаються дозволені адреси у лог файлі.
Записує результат аналізу лог-файлу до файлу output_file_path, у вигляді <IP адерса> - <кількість входженнь>.
Обробити можливі винятки, такі як відсутність вхідного файлу (FileNotFoundError) або помилки запису до вихідного файлу (IOError), виводячи інформативні повідомлення.
"""
import sys


def filter_ips(input_file_path, output_file_path, allowed_ips):
    ip_counts = {ip: 0 for ip in allowed_ips}
    
    try:
        with open(input_file_path, 'r') as input_file:
            for line in input_file:
                try:
                    ip = line.split()[0]
                    if ip in ip_counts:
                        ip_counts[ip] += 1
                except IndexError:
                    continue 
        
        with open(output_file_path, 'w') as output_file:
            for ip, count in ip_counts.items():
                output_file.write(f"{ip} - {count}\n")
                
    except FileNotFoundError:
        print(f"Error: Input file not found - {input_file_path}")
        return {}
    except IOError as e:
        print(f"Error processing files: {e}")
        return {}
    
    return ip_counts


if __name__ == "__main__":

    ALLOWED_IPS = [
        '50.131.51.216',
        '212.197.170.45',
        '108.32.74.68'
    ]
    
    
    if len(sys.argv) != 3:
        print("Usage: python lb3z3.py <input_log_file> <output_results_file>")
        print("Example: python lb3z3.py access.log ip_counts.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    results = filter_ips(input_file, output_file, ALLOWED_IPS)
    
    print("\nIP Address Count Results:")
    print("========================")
    for ip, count in results.items():
        print(f"{ip}: {count} occurrences")
    print("========================")
    print(f"Results saved to {output_file}")
