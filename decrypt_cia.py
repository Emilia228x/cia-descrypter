#!/usr/bin/env python3
"""
CIA Decryptor using pyctr (Финальная версия с правильными офсетами CIA)
Использование: python3 decrypt_cia.py <input.cia> <output.cia> [--boot9 path] [--movable path]
"""

import sys
import os
import argparse
import tempfile
import shutil
from hashlib import sha256

def readle(b): return int.from_bytes(b, byteorder='little')
def readbe(b): return int.from_bytes(b, byteorder='big')
def roundup(val, align): return ((val + align - 1) // align) * align

# Стандартные типы сигнатур TMD и их размеры (sig_size, sig_padding)
signature_types = {
    0x00010000: (0x200, 0x3C), 0x00010001: (0x100, 0x3C), 0x00010002: (0x3C, 0x40),
    0x00010003: (0x200, 0x3C), 0x00010004: (0x100, 0x3C), 0x00010005: (0x3C, 0x40),
}

def setup_keys(boot9_path, movable_path):
    if not boot9_path and not movable_path:
        return None
    temp_dir = tempfile.TemporaryDirectory(prefix="pyctr_keys_")
    if boot9_path:
        if not os.path.exists(boot9_path): sys.exit(f"✖️ boot9.bin не найден: {boot9_path}")
        shutil.copy(boot9_path, os.path.join(temp_dir.name, 'boot9.bin'))
    if movable_path:
        if not os.path.exists(movable_path): sys.exit(f"✖️ movable.sed не найден: {movable_path}")
        shutil.copy(movable_path, os.path.join(temp_dir.name, 'movable.sed'))
    os.environ['CTR_COMMON_DIR'] = temp_dir.name
    print(f"✨ Ключи загружены во временную папку: {temp_dir.name}")
    return temp_dir

def decrypt_cia(input_file, output_file):
    try:
        from pyctr.type.cia import CIAReader, CIASection
        from pyctr.type.ncch import NCCHSection
    except ImportError:
        sys.exit("✖️ Ошибка: pyctr не установлена. ('pip install pyctr')")

    if not os.path.exists(input_file):
        sys.exit(f"✖️ Файл {input_file} не существует.")

    print(f"[*] Открываю {input_file}...")
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        try:
            cia = CIAReader(f_in)
        except Exception as e:
            sys.exit(f"✖️ Ошибка загрузки CIA: {e}. Проверьте ключи.")
            
        # Читаем первые 32 байта, чтобы узнать размеры секций
        f_in.seek(0)
        header_data = f_in.read(0x20)
        
        archive_header_size = readle(header_data[0x0:0x4])
        cert_chain_size = readle(header_data[0x8:0xC])
        ticket_size = readle(header_data[0xC:0x10])
        tmd_size = readle(header_data[0x10:0x14])
        content_size = readle(header_data[0x18:0x20])
        
        ALIGN_SIZE = 64
        
        # 🔥 Вычисляем ПРАВИЛЬНЫЕ абсолютные офсеты от начала файла (без сдвига на 0x20)
        archive_header_offset = 0
        cert_chain_offset = roundup(archive_header_size, ALIGN_SIZE)
        ticket_offset = cert_chain_offset + roundup(cert_chain_size, ALIGN_SIZE)
        tmd_offset = ticket_offset + roundup(ticket_size, ALIGN_SIZE)
        content_offset = tmd_offset + roundup(tmd_size, ALIGN_SIZE)
        meta_offset = content_offset + roundup(content_size, ALIGN_SIZE)
        
        # 1. Копируем Archive Header
        f_out.seek(archive_header_offset)
        with cia.open_raw_section(CIASection.ArchiveHeader) as s: 
            f_out.write(s.read())
            
        # 2. Копируем Certificate Chain
        f_out.seek(cert_chain_offset)
        with cia.open_raw_section(CIASection.CertificateChain) as s: 
            f_out.write(s.read())
            
        # 3. Копируем Ticket
        f_out.seek(ticket_offset)
        with cia.open_raw_section(CIASection.Ticket) as s: 
            f_out.write(s.read())
            
        # 4. Расшифровываем контент
        tmd = cia.tmd
        curr_offset = content_offset
        chunk_updates = {} 
        
        for record in tmd.chunk_records:
            cindex = record.cindex
            is_srl = (cindex == 0 and tmd.title_id[3:5] == '48')
            
            if not is_srl and cindex in cia.contents:
                ncch = cia.contents[cindex]
                print(f"[*] Расшифровываю контент с индексом {cindex}...")
                with ncch.open_raw_section(NCCHSection.FullDecrypted) as ncch_file:
                    data = ncch_file.read()
                    ncch_hash = sha256(data).digest()
                    if len(data) < record.size: data += b'\x00' * (record.size - len(data))
                    elif len(data) > record.size: data = data[:record.size]
                    f_out.seek(curr_offset)
                    f_out.write(data)
            else:
                print(f"[*] Копирую SRL/неизвестный контент с индексом {cindex}...")
                with cia.open_raw_section(cindex) as section:
                    data = section.read()
                    ncch_hash = sha256(data).digest()
                    f_out.seek(curr_offset)
                    f_out.write(data)
                    
            chunk_updates[cindex] = {
                'hash': ncch_hash,
                'was_encrypted': record.type.encrypted
            }
            curr_offset += record.size
            
        # 5. Хирургический патчинг TMD
        # Читаем оригинальный TMD из входного файла по правильному офсету
        f_in.seek(tmd_offset)
        tmd_data = bytearray(f_in.read(tmd_size))
        
        sig_type = readbe(tmd_data[0:4])
        if sig_type not in signature_types:
            sys.exit(f"✖️ Неизвестный тип сигнатуры TMD: {sig_type:#010x}")
            
        sig_size, sig_padding = signature_types[sig_type]
        header_offset = 4 + sig_size + sig_padding
        info_records_offset = header_offset + 0xC4
        chunk_records_offset = info_records_offset + 0x900
        
        # Патчим Chunk Records
        for i, record in enumerate(tmd.chunk_records):
            cr_offset = chunk_records_offset + i * 0x30
            update = chunk_updates.get(record.cindex)
            
            if update:
                if update['was_encrypted']:
                    orig_type = readbe(tmd_data[cr_offset + 6 : cr_offset + 8])
                    new_type = orig_type & ~0x01  # Снимаем бит Encrypted
                    tmd_data[cr_offset + 6 : cr_offset + 8] = new_type.to_bytes(2, 'big')
                tmd_data[cr_offset + 16 : cr_offset + 48] = update['hash']
                
        # Патчим Info Records
        for i in range(64):
            ir_offset = info_records_offset + i * 0x24
            index_offset = readbe(tmd_data[ir_offset : ir_offset + 2])
            command_count = readbe(tmd_data[ir_offset + 2 : ir_offset + 4])
            if command_count == 0 and index_offset == 0: continue
            
            chunks_to_hash = tmd_data[chunk_records_offset + index_offset * 0x30 : 
                                        chunk_records_offset + (index_offset + command_count) * 0x30]
            ir_hash = sha256(chunks_to_hash).digest()
            tmd_data[ir_offset + 4 : ir_offset + 36] = ir_hash
            
        # Обновляем глобальный хэш Info Records в заголовке TMD
        info_records_block = tmd_data[info_records_offset : info_records_offset + 0x900]
        header_ir_hash = sha256(info_records_block).digest()
        tmd_data[header_offset + 0xA4 : header_offset + 0xC4] = header_ir_hash
        
        # Записываем пропатченный TMD
        f_out.seek(tmd_offset)
        f_out.write(tmd_data)
        
        # 6. Meta раздел
        if CIASection.Meta in cia.sections:
            f_out.seek(meta_offset)
            with cia.open_raw_section(CIASection.Meta) as s: f_out.write(s.read())
                
        f_out.truncate(cia.total_size)
        
    print(f"🌸 Успех! Расшифрованный CIA сохранен в: {output_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="✨ CIA Decryptor using pyctr (Final Edition)")
    parser.add_argument("input", help="Путь к зашифрованному .cia файлу")
    parser.add_argument("output", help="Путь для сохранения расшифрованного .cia файла")
    parser.add_argument("--boot9", help="Путь к файлу boot9.bin", default=None)
    parser.add_argument("--movable", help="Путь к файлу movable.sed", default=None)
    args = parser.parse_args()
    
    temp_keys = setup_keys(args.boot9, args.movable)
    try:
        decrypt_cia(args.input, args.output)
    finally:
        if temp_keys: temp_keys.cleanup()
