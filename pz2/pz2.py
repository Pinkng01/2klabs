import hashlib
from abc import ABC, abstractmethod

class User(ABC):
    def __init__(self, username, password, is_active=True):
        self.username = username
        self.password_hash = self._hash_password(password)
        self.is_active = is_active
    
    def _hash_password(self, password):
        """Хешування пароля за допомогою SHA-256"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def verify_password(self, password):
        """Перевірка пароля"""
        return self.password_hash == self._hash_password(password)
    
    @abstractmethod
    def get_role(self):
        """Абстрактний метод для отримання ролі користувача"""
        pass

class Administrator(User):
    def __init__(self, username, password, is_active=True, permissions=None):
        super().__init__(username, password, is_active)
        self.permissions = permissions or ["manage_users"]
    
    def get_role(self):
        return "Administrator"
    
    def has_permission(self, permission):
        return permission in self.permissions

class RegularUser(User):
    def __init__(self, username, password, is_active=True, last_login=None):
        super().__init__(username, password, is_active)
        self.last_login = last_login
    
    def get_role(self):
        return "RegularUser"

class GuestUser(User):
    def __init__(self, username, password="", is_active=True):
        super().__init__(username, password, is_active)
    
    def get_role(self):
        return "GuestUser"
    
    def verify_password(self, password):
        # Гості не мають пароля
        return True

class AccessControl:
    def __init__(self):
        self.users = {}
    
    def add_user(self, user):
        """Додавання нового користувача"""
        if user.username in self.users:
            raise ValueError(f"Користувач з іменем '{user.username}' вже існує")
        self.users[user.username] = user
    
    def authenticate_user(self, username, password):
        """Аутентифікація користувача"""
        user = self.users.get(username)
        if user and user.is_active and user.verify_password(password):
            if isinstance(user, RegularUser):
                user.last_login = "now" 
            return user
        return None
    
    def list_users(self):
        """Виведення списку всіх користувачів"""
        return list(self.users.values())

def cli_interface():
    """Простий CLI інтерфейс для взаємодії з користувачем"""
    access_control = AccessControl()
    
    try:
        access_control.add_user(Administrator("admin", "admin123"))
        access_control.add_user(RegularUser("user1", "password1"))
        access_control.add_user(GuestUser("guest"))
    except ValueError as e:
        print(f"Помилка при створенні тестових користувачів: {e}")
    
    print("Ласкаво просимо до системи контролю доступу!")
    
    while True:
        print("\nМеню:")
        print("1. Увійти в систему")
        print("2. Переглянути список користувачів (тільки для адміністратора)")
        print("3. Вийти")
        
        choice = input("Виберіть опцію: ")
        
        if choice == "1":
            username = input("Ім'я користувача: ")
            password = input("Пароль: ") 
            
            user = access_control.authenticate_user(username, password)
            
            if user:
                print(f"\nВітаємо, {user.username}! Ваша роль: {user.get_role()}")
                
                if isinstance(user, Administrator):
                    print("Ви маєте додаткові права адміністратора")
                    print(f"Доступні права: {', '.join(user.permissions)}")
            else:
                print("Невірне ім'я користувача або пароль, або обліковий запис не активний")
        
        elif choice == "2":
            # Спроба автентифікуватися як адміністратор
            username = input("Ім'я адміністратора: ")
            password = input("Пароль: ")
            
            user = access_control.authenticate_user(username, password)
            
            if user and isinstance(user, Administrator):
                print("\nСписок користувачів:")
                for u in access_control.list_users():
                    status = "активний" if u.is_active else "неактивний"
                    print(f"- {u.username} ({u.get_role()}), статус: {status}")
            else:
                print("Доступ заборонено. Потрібні права адміністратора")
        
        elif choice == "3":
            print("Дякуємо за використання нашої системи!")
            break
        
        else:
            print("Невірний вибір. Спробуйте ще раз.")

if __name__ == "__main__":
    cli_interface()