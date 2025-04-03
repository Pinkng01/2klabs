# 1. Отримати курси евро за попередній тиждень, вивести на екран дату + курс
# 2. З отриманого словника побудувати графк зміни курсу за тиждень
# URL for request https://bank.gov.ua/NBU_Exchange/exchange_site?start=20250317&end=20250321&valcode=eur&json

import json
import requests
import matplotlib.pyplot as plt

nbu_response = requests.get(
    "https://bank.gov.ua/NBU_Exchange/exchange_site?start=20250301&end=20250403&valcode=usd&json"
)

converted_response = json.loads(nbu_response.content)

dates = []
rates = []

print("usd Exchange Rates from NBU:")
for item in converted_response:
    date_str = item['exchangedate']  # Format: "dd.mm.yyyy"
    rate = item['rate']
    
    dates.append(date_str)
    rates.append(rate)
    
    print(f"{date_str}: {rate} UAH")

plt.figure(figsize=(10, 6))
plt.plot(dates, rates, marker='o', linestyle='-', color='b')
plt.title('usd to UAH Exchange Rate (NBU)')
plt.xlabel('Date')
plt.ylabel('Exchange Rate (UAH)')
plt.grid(True)
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()