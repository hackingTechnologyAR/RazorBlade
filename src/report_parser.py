



import xml.etree.ElementTree as ET
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import os
import re
from openpyxl.utils import get_column_letter

def extract_dmarc_tag(text, tag):
    """Вспомогательная функция для парсинга тегов DMARC (p, rua, ruf)"""
    if not text or pd.isna(text):
        return 'N/A'
    # Ищем паттерн вида p=reject или rua=mailto:d@rua.com
    match = re.search(r'\b' + tag + r'=\s*([^;]+)', text, re.IGNORECASE)
    if match:
        val = match.group(1).strip()
        # Очищаем email от префиксов mailto:
        val = val.replace('mailto:', '')
        return val
    return 'None' if tag == 'p' else 'Not Configured'

def parse_xml_to_dataframe(xml_file):
    if not os.path.exists(xml_file):
        print(f"[-] Файл {xml_file} не найден! Сначала запустите сканер.")
        return None

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError:
        print(f"[-] Ошибка чтения XML. Возможно, файл поврежден или сканирование прервано.")
        return None

    records = []

    for resp in root.findall('response'):
        ts = resp.find('timestamp').text if resp.find('timestamp') is not None else None
        domain = resp.find('domain').text if resp.find('domain') is not None else 'Unknown'
        dns_server = resp.find('dns_server').text if resp.find('dns_server') is not None else 'Unknown'
        status = resp.find('status').text if resp.find('status') is not None else 'Unknown'
        
        formatted_time = datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S') if ts else 'Unknown'

        record = resp.find('record')
        if record is not None:
            rec_type = record.find('type').text if record.find('type') is not None else 'N/A'
            value = record.find('value').text if record.find('value') is not None else 'N/A'
            ttl = record.find('ttl').text if record.find('ttl') is not None else '0'
        else:
            rec_type, value, ttl = 'N/A', 'N/A', '0'

        # Извлекаем параметры DMARC для глубокой аналитики
        dmarc_policy = extract_dmarc_tag(value, 'p')
        rua_reports = extract_dmarc_tag(value, 'rua')

        records.append({
            'Время': formatted_time,
            'Target Domain': domain,
            'DNS Resolver': dns_server,
            'Response Status': status,
            'Record Type': rec_type,
            'DMARC Policy (p=)': dmarc_policy,
            'Aggregate Reports (rua)': rua_reports,
            'Full Raw Value': value,
            'TTL': int(ttl)
        })

    return pd.DataFrame(records)

def generate_report():
    xml_filename = 'scan_results.xml'
    df = parse_xml_to_dataframe(xml_filename)
    
    if df is None or df.empty:
        print("[-] Нет данных для обработки.")
        return

    # 1. Генерация красивой Excel-таблицы
    excel_filename = 'scan_report.xlsx'
    with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Результаты сканирования')
        
        worksheet = writer.sheets['Результаты сканирования']
        for col_idx, col in enumerate(worksheet.columns, start=1):
            max_len = max(len(str(cell.value or '')) for cell in col)
            col_letter = get_column_letter(col_idx)
            worksheet.column_dimensions[col_letter].width = max(max_len + 3, 12)
            
    print(f"[+] Расширенная Excel-таблица успешно создана: {excel_filename}")

    # 2. Построение графиков ответов (Умная покраска по ключевым словам)
    plt.figure(figsize=(8, 5))
    status_counts = df['Response Status'].value_counts()
    
    colors = []
    for status in status_counts.index:
        status_upper = status.upper()
        if 'NOERROR' in status_upper:
            colors.append('#2ecc71')  # Зеленый для успешных
        elif 'TIMEOUT' in status_upper:
            colors.append('#e74c3c')  # Красный для таймаутов
        else:
            colors.append('#3498db')  # Синий для остальных (NXDOMAIN, SERVFAIL)
    
    status_counts.plot(kind='bar', color=colors, edgecolor='black', zorder=3)
    
    plt.title('Распределение статусов ответов DNS-сканера', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Статус ответа', fontsize=11, labelpad=10)
    plt.ylabel('Количество пакетов', fontsize=11, labelpad=10)
    plt.xticks(rotation=15)  # Немного повернем текст для читаемости длинных статусов
    plt.grid(axis='y', linestyle='--', alpha=0.7, zorder=0)
    plt.tight_layout()
    
    chart_filename = 'scan_statistics.png'
    plt.savefig(chart_filename, dpi=150)
    plt.close()
    print(f"[+] График статистики успешно сохранен: {chart_filename}")

if __name__ == '__main__':
    generate_report()
