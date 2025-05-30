"""
Створіть функцію generate_file_hashes(*file_paths), яка приймає список шляхів до файлів. Для кожного файлу у списку функція повинна:
Відкрити файл у бінарному режимі для читання.
Обчислити хеш SHA-256 вмісту файлу.
Зберегти результати у словнику, де ключем є шлях до файлу, а значенням - його SHA-256 хеш (у шістнадцятковому форматі).
Обробити можливі винятки, такі як відсутність файлу (FileNotFoundError) або помилки читання файлу (IOError), виводячи відповідне повідомлення.
Повернути словник з хешами файлів.
Для обчислення хешів скористайтеся бібліотекою hashlib.
"""
import hashlib
import sys

def generate_file_hashes(*file_paths):
    file_hashes = {}
    
    for file_path in file_paths:
        try:
            with open(file_path, 'rb') as f:
                sha256_hash = hashlib.sha256()
                
                # Read and update hash in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                
                file_hashes[file_path] = sha256_hash.hexdigest()
                
        except FileNotFoundError:
            print(f"Warning: File not found - {file_path}")
        except IOError as e:
            print(f"Warning: Could not read file {file_path} - {e}")
        except Exception as e:
            print(f"Warning: Unexpected error processing {file_path} - {e}")
    
    return file_hashes


if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        print("Usage: python lb3z2.py <file1> [file2] [file3] ...")
        print("Example: python lb3z2.py document.txt image.jpg")
        sys.exit(1)
    
    files_to_hash = sys.argv[1:]
    hashes = generate_file_hashes(*files_to_hash)
    
    print("\nFile Hashes (SHA-256):")
    print("======================")
    for file_path, file_hash in hashes.items():
        print(f"{file_path}: {file_hash}")
    print("======================")
    print(f"Processed {len(hashes)} of {len(files_to_hash)} files")
