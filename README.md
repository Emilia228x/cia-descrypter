# ✨ CIA Decryptor / Дешифратор CIA

**[English](#english)** | **[Русский](#русский)**

---

<a id="english"></a>
## 🇬🇧 English

A lightweight Python script to decrypt Nintendo 3DS `.cia` files using the [pyctr](https://github.com/ihaveamac/pyctr) library.  
The script performs surgical TMD patching, preserving the original file structure and ensuring full compatibility with `ctrtool`, FBI, and emulators (Citra/Lime3DS).

### 📦 Installation

1. Make sure you have **Python 3.8+** installed.
2. Clone the repository and install dependencies:
   ```bash
   git clone https://github.com/Emilia228x/cia-decryptor.git
   cd cia-decryptor
   pip install -r requirements.txt
