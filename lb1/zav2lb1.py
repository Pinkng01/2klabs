#Створіть словник, де ключі - це назви продуктів,
# а значення - їх кількість на складі. Напишіть функцію, 
# яка приймає назву продукту та кількість,
# і оновлює словник відповідно до додавання або видалення продуктів.
# Додатково: створіть список продуктів, в яких кількість менше ніж 5.

stockpile = {
    "apples": 100,
    "bananas": 1,
    "batteries": 7,
    "cards": 7,
    "jam": 2
}

def update_stockpile(product, quantity):
    if product in stockpile:
        stockpile[product] += quantity
    else:
        stockpile[product] = quantity

    if stockpile[product] < 0:
        stockpile[product] = 0

def delete_product(product):
    if product in stockpile:
        del stockpile[product]
        print(f"Product '{product}'deleted.")
    else:
        print(f"Product '{product}'not found.")


def get_low_stock_products():
    return [product for product, qty in stockpile.items() if qty < 5]


print("Base stockpile:", stockpile)


update_stockpile("apples", 5)
print("Stockpile updated with 5 apples:", stockpile)


delete_product("bananas")
print("Stockpiler after removing bananas:", stockpile)

low_stock = get_low_stock_products()
print("Продукти з кількістю менше 5:", low_stock)
