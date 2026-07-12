# ✨ CIA Decryptor

Лёгкий Python-скрипт для дешифрования `.cia` файлов Nintendo 3DS с использованием библиотеки [pyctr](https://github.com/ihaveamac/pyctr).  
Скрипт выполняет хирургический патчинг TMD, сохраняя оригинальную структуру файла и обеспечивая полную совместимость с `ctrtool`, FBI и эмуляторами (Citra/Lime3DS).

## 📦 Установка

1. Убедитесь, что у вас установлен **Python 3.8+**.
2. Клонируйте репозиторий и установите зависимости:
   ```bash
   git clone https://github.com/Emilia228x/cia-decryptor.git
   cd cia-decryptor
   pip install -r requirements.txt
