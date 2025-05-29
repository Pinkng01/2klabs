# Завдання
# За допомогою Python створіть БД sqlite3 та таблицю в якій зберігаються облікові записи користувачів. Таблиця повинна мати як мінімум наступні стовпці:
# login - ім'я користувача
# password -  зашифрованний пароль у вигляді хешу
# full_name - повне ПІБ користувача. 
# Розробіть програму на python, яка містить у собі наступні функції:
# Додавання нових користувачів
# Оновлення паролю користувачів
# Перевірки автентифікації, тобто введеного паролю користувача. пароль користувач вводить з консолі, зчитування за допомогою методу input() 
# Завантажити виконане завдання та файл БД на персональний github

import sqlite3
import hashlib

# Функція для створення бази даних та таблиці
def create_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            login TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def add_user(login, password, full_name):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f'''
        INSERT INTO users (login, password, full_name)
        VALUES ('{login}', '{hashed_password}', '{full_name}')
    ''')
    conn.commit()
    conn.close()

def update_password(login, new_password):
    hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f'''
        UPDATE users SET password = '{hashed_password}'
        WHERE login = '{login}'
    ''')
    conn.commit()
    conn.close()

def authenticate(login, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f'''
        SELECT * FROM users
        WHERE login = '{login}' AND password = '{hashed_password}'
    ''')#Тут ми можемо обійти автентифікацію якщо в графу пароль або логін введемо "' OR '1'='1' --"
    #це і є так завана SQL injection яка так часто використовується у CTF-ках.
    user = cursor.fetchone()
    conn.close()
    return user is not None


def main():
    create_database()
    
    while True:
        print("\n1. Додати нового користувача")
        print("2. Оновити пароль користувача")
        print("3. Перевірити автентифікацію")
        print("4. Вийти")
        
        choice = input("Виберіть опцію: ")
        
        if choice == '1':
            login = input("Введіть логін: ")
            password = input("Введіть пароль: ")
            full_name = input("Введіть повне ім'я: ")
            add_user(login, password, full_name)
            print("Користувача додано!")
            
        elif choice == '2':
            login = input("Введіть логін: ")
            new_password = input("Введіть новий пароль: ")
            update_password(login, new_password)
            print("Пароль оновлено!")
            
        elif choice == '3':
            login = input("Введіть логін: ")
            password = input("Введіть пароль: ")
            if authenticate(login, password):
                print("Автентифікація успішна!")
            else:
                print("Невірний логін або пароль!")
                
        elif choice == '4':
            break
            
        else:
            print("Невірний вибір, спробуйте ще раз.")

if __name__ == "__main__":
    main()

