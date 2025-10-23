import hashlib
import sys

class BloomFilter:
    '''Реалізація фільтра Блума для ефективної перевірки належності елементів'''
    def __init__(self, size: int, num_hashes: int):
        # Перевірка коректності вхідних даних
        if not (isinstance(size, int) and size > 0):
            raise ValueError("Розмір (size) має бути додатним цілим числом")
        if not (isinstance(num_hashes, int) and num_hashes > 0):
            raise ValueError("Кількість хеш-функцій (num_hashes) має бути додатним цілим числом")

        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [0] * size

    def _get_hashes(self, item: str):
        '''Генерує 'num_hashes' різних індексів для елемента'''
        hashes = []

        # Обробка некоректних типів даних
        if item is None:
            return hashes
        
        # Перетворюємо рядок на байти для хешування
        item_bytes = str(item).encode('utf-8')

        # Генеруємо два базові хеші, використовуючи різні алгоритми для кращого розподілу
        hash1 = int(hashlib.md5(item_bytes).hexdigest(), 16)
        hash2 = int(hashlib.sha256(item_bytes).hexdigest(), 16)

        # Генеруємо 'num_hashes' комбінованих хешів
        for i in range(self.num_hashes):
            combined_hash = (hash1 + i * hash2) % self.size
            hashes.append(combined_hash)

        return hashes

    def add(self, item: str):
        '''Додає елемент до фільтра Блума'''
        indices = self._get_hashes(item)
        for index in indices:
            self.bit_array[index] = 1

    def check(self, item: str) -> bool:
        '''Перевіряє, чи може елемент належати множині'''
        indices = self._get_hashes(item)

        # Якщо елемент некоректний (None), він точно не в фільтрі
        if not indices and item is None:
            return False
        
        for index in indices:
            # Якщо хоча б один біт = 0, елемента точно немає
            if self.bit_array[index] == 0:
                return False
            
        # Імовірно, елемент є в множині
        return True
    
def check_password_uniqueness(bloom_filter: BloomFilter, passwords: list) -> dict:
    '''Перевіряє унікальність паролів за допомогою фільтра Блума'''
    results = {}

    if not isinstance(passwords, (list, tuple)):
        print("Помилка: Вхідні дані мають бути списком або кортежем", file=sys.stderr)
        return results

    for password in passwords:
        # Обробка некоректних значень
        if password is None:
            results[str(password)] = "некоректний (None)"
            continue

        if bloom_filter.check(password):
            # Якщо check=True, пароль *ймовірно* вже використаний
            results[password] = "вже використаний"
        else:
            # Якщо check=False, пароль точно унікальний
            results[password] = "унікальний"

    return results

def main():
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")

    print("\nДодаткова перевірка (порожні та None):\n")

    # Додамо порожній пароль до "існуючих"
    bloom_extra = BloomFilter(size=100, num_hashes=3)
    bloom_extra.add("")

    passwords_extra = ["", "another_pass", None]
    results_extra = check_password_uniqueness(bloom_extra, passwords_extra)
    
    for password, status in results_extra.items():
        print(f"Пароль '{password}' — {status}.")

if __name__ == "__main__":
    main()