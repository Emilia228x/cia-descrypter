# ✨ CIA Decryptor
#EN


A lightweight Python script to decrypt Nintendo 3DS `.cia` files using the [pyctr](https://github.com/ihaveamac/pyctr) library. 
The script performs TMD surgical patching, preserving the original file structure and providing full compatibility with `ctrtool`, FBI and emulators.


## 📦 Installation


1. Make sure you have Python 3.8+ installed.
2. Clone the repository:
   ```bash
   git clone https://github.com/Emilia228x/cia-decryptor.git
   cd cia-decryptor
   
## 🚀 Usage and arguments


The script takes two required positional arguments and two optional flags to specify keys.


### Syntax
```bash
python decrypt_cia.py <input> <output> [--boot9 PATH] [--movable PATH]

# ✨ CIA Decryptor
#RU

Лёгкий Python-скрипт для дешифрования `.cia` файлов Nintendo 3DS с использованием библиотеки [pyctr](https://github.com/ihaveamac/pyctr). 
Скрипт выполняет хирургический патчинг TMD, сохраняя оригинальную структуру файла и обеспечивая полную совместимость с `ctrtool`, FBI и эмуляторами.

## 📦 Установка

1. Убедитесь, что у вас установлен Python 3.8+.
2. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/Emilia228x/cia-decryptor.git
   cd cia-decryptor
   
## 🚀 Использование и аргументы

Скрипт принимает два обязательных позиционных аргумента и два опциональных флага для указания ключей.

### Синтаксис
```bash
python decrypt_cia.py <input> <output> [--boot9 PATH] [--movable PATH]
