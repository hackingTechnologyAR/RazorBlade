import sys
import os

def generate_brute_list():
    if len(sys.argv) < 2:
        print("[-] Использование: python brute_gen.py <целевой_домен>")
        print("[-] Пример: python brute_gen.py shopify.com")
        return

    target_domain = sys.argv[1].strip().lower()
    wordlist_path = 'wordlist.txt'
    output_path = 'domains.txt'

    if not os.path.exists(wordlist_path):
        print(f"[-] Файл {wordlist_path} не найден! Создайте его сначала.")
        return

    with open(wordlist_path, 'r') as wf:
        subdomains = [line.strip() for line in wf if line.strip() and not line.startswith('#')]

    final_list = []
    final_list.append(target_domain)
    
    for sub in subdomains:
        final_list.append(f"{sub}.{target_domain}")

    with open(output_path, 'w') as of:
        for item in final_list:
            of.write(f"{item}\n")

    print(f"[+] Сгенерировано целей для брутфорса: {len(final_list)}")
    print(f"[+] Файл {output_path} успешно обновлен и готов к сканированию.")

if __name__ == '__main__':
    generate_brute_list()
