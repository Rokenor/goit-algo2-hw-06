import json
import time
import mmh3
import math

LOG_FILE = 'lms-stage-access.log'

class HyperLogLog:
    '''Реалізація алгоритму HyperLogLog для оцінки кількості унікальних елементів'''
    def __init__(self, p=14):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()

    def _get_alpha(self):
        '''Повертає константу альфа в залежності від кількості регістрів'''
        if self.m == 16:
            return 0.673
        elif self.m == 32:
            return 0.697
        elif self.m == 64:
            return 0.709
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        '''Додає елемент до HyperLogLog'''
        # 32-бітове хешування з використанням mmh3
        x = mmh3.hash(str(item), signed=False)

        # Використовуємо перші p біт (молодші) для індексу
        j = x & (self.m - 1)

        # Решта біт (старші) для підрахунку нулів
        w = x >> self.p

        # Оновлюємо відповідний регістр
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        '''Підрахунок позиції першого встановленого біта'''
        if w == 0:
            return 32 - self.p + 1
        
        rho = 1
        while (w & 1) == 0:
            rho += 1
            w >>= 1

        return rho

    def count(self):
        '''Оцінка кількості унікальних елементів'''

        # Оцінка за допомогою гармонійного середнього
        Z = sum(2 ** -r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        # Корекція для малих значень
        V = self.registers.count(0)
        if V > 0:
            E_star = self.m * math.log(self.m / V)
            if E <= (5 * self.m /2):
                E = E_star

        # Корекція для великих значень
        H = (1 / 30) * (2**32)
        if E > H:
            E = -(2**32) * math.log(1 - E / 2**32)

        return E
    
def load_ips_from_log(filename):
    # Завантаження IP-адрес з лог-файлу
    ips = []
    processed_lines = 0
    ignored_lines = 0

    print(f"Початок завантаження IP-адрес з файлу: {filename}")
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                processed_lines += 1
                try:
                    data = json.loads(line)
                    ip = data.get('remote_addr')
                    if ip:
                        ips.append(ip)
                    else:
                        ignored_lines += 1
                except (json.JSONDecodeError, TypeError, KeyError):
                    ignored_lines += 1
    except FileNotFoundError:
        print(f"Помилка: Файл {filename} не знайдено")
        return None
    except Exception as e:
        print(f"Виникла помилка при читанні файлу: {e}")
        return None
    
    print(f"Заватаення завершено")
    print(f"Оброблено рядків: {processed_lines}")
    print(f"Ігноровано рядків: {ignored_lines}")
    print(f"Знайдено IP-адрес: {len(ips)}")
    return ips

def exact_count(ips):
    '''Точний підрахунок унікальних елементів за допомогою set'''
    print("Виконується точний підрахунок (set)...")
    start_time = time.perf_counter()

    unique_ips = set(ips)
    count = len(unique_ips)

    end_time = time.perf_counter()
    execution_time = end_time - start_time

    return count, execution_time

def hll_count(ips):
    '''Наближений підрахунок унікальних елементів за допомогою HyperLogLog'''
    p_value = 14  # Кількість біт для індексації регістрів
    print(f"Виконується наближений підрахунок (HLL, p={p_value})...")
    start_time = time.perf_counter()

    hll = HyperLogLog(p=p_value)

    for ip in ips:
        hll.add(ip)

    count = hll.count()

    end_time = time.perf_counter()
    execution_time = end_time - start_time

    return count, execution_time

def main():
    # Завантаження IP-адрес з лог-файлу
    ips_list = load_ips_from_log(LOG_FILE)

    if ips_list is None or not ips_list:
        print("Не вдалося завантажити дані. Завершення роботи")
        return
    
    # Точний підрахунок унікальних IP-адрес
    exact_unique_count, exact_time = exact_count(ips_list)

    # Наближений підрахунок унікальних IP-адрес за допомогою HyperLogLog
    hll_unique_count, hll_time = hll_count(ips_list)

    # Виведення результатів
    print("\n" + "="*55)
    print("Результати порівняння:")
    print("="*55)

    print(f"{'':<25} {'Точний підрахунок':<20} {'HyperLogLog':<20}")
    print("-" * 65)
    print(f"{'Унікальні елементи':<25} {exact_unique_count:<20.1f} {hll_unique_count:<20.1f}")
    print(f"{'Час виконання (сек.)':<25} {exact_time:<20.4f} {hll_time:<20.4f}")

    # Розрахунок відносної помилки
    error_percent = (abs(exact_unique_count - hll_unique_count) / exact_unique_count) * 100
    print("-" * 65)
    print(f"Похибка HyperLogLog: {error_percent:.2f}%")

if __name__ == "__main__":
    main()