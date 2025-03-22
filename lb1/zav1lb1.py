#Напишіть функцію, яка приймає рядок як вхідні дані та повертає словник, 
#де ключі - це унікальні слова в рядку, а значення - кількість їх появ.
#Створіть та виведіть на екран список, 
#де зберігаються слова, що зустрічаються більше 3 разів. 
def count_words(text):

    words = text.split()
    
    word_count = {}
    
    for word in words:
        word = word.strip('.,!?').lower()
        if word in word_count:
            word_count[word] += 1
        else:
            word_count[word] = 1
    
    return word_count
def get_words_occurring_more_than_three_times(word_count):

    return [word for word, count in word_count.items() if count >= 3]

if __name__ == "__main__":
    text = "Yo yo, test text sequence text text!!!!., test, test??"
    word_count = count_words(text)
    print("Output dictionary:", word_count)

    frequent_words = get_words_occurring_more_than_three_times(word_count)
    print("Words that occur more than 3 times:", frequent_words)