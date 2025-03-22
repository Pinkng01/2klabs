#Створіть словник в якому зберігаються ім'я користувача(login)
# , зашифрований пароль та повне ПІБ користувача. 
# Для хешування пароля використовуйте функцію hashlib.md5().
# Зробіть функцію перевірки введеного паролю користувача;
# пароль користувач вводить з консолі, зчитування за допомогою методу input()


import hashlib

users = {}

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def register_user():
    login = input("Enter your username: ")
    if login in users:
        print("A user with this username already exists!")
        return

    password = input("Enter your password: ")
    full_name = input("Enter your full name: ")

    users[login] = {
        "password_hash": hash_password(password),
        "full_name": full_name
    }
    print("User registered successfully!")

def check_password(login, password):
    if login in users and users[login]["password_hash"] == hash_password(password):
        return True
    return False

def login_user():
    login = input("Enter your username: ")
    password = input("Enter your password: ")

    if check_password(login, password):
        print(f"Welcome, {users[login]['full_name']}! You have successfully logged in.")
    else:
        print("Invalid username or password.")

def main():
    while True:
        print("\nMenu:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            print("Exiting!")
            print(users)
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()