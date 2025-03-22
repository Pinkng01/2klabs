#Статистика продажів. Створіть список словників,
#  де кожен словник представляє продаж з ключами:
#  "продукт", "кількість", "ціна".
#  Напишіть функцію, яка обчислює загальний дохід для
#  кожного продукту та повертає словник,
#  де ключі - це назви продуктів, а значення - загальний дохід.
#  Створіть список продуктів, що принесли дохід більший ніж 1000.

sales = [
    {"prod": "apple", "amount": 10, "price": 50},
    {"prod": "car", "amount": 5, "price": 300},
    {"prod": "beer", "amount": 7, "price": 5},
    {"prod": "cat", "amount": 2, "price": 1000},
    {"prod": "computer", "amount": 8, "price": 3},
]

def calculate_total_revenue(sales):
    revenue = {}
    for sale in sales:
        product = sale["prod"]
        total = sale["amount"] * sale["price"]
        if product in revenue:
            revenue[product] += total
        else:
            revenue[product] = total
    return revenue

def get_high_revenue_products(revenue):
    return [(product, total) for product, total in revenue.items() if total > 1000]
#Тут юзаем генератор списка который проверяет если тотал в паре из revenue больше 1000 

for sale in sales:
    print(sale)

total_revenue = calculate_total_revenue(sales)
print("Total revenue:", total_revenue)

high_revenue_products = get_high_revenue_products(total_revenue)
print("high revenue prod.( > 1000):", high_revenue_products)
