


// parser.c

// parser.c — Безопасный бинарный парсер DNS-имен для утилиты RazorBlade

#include "parser.h"
#include <string.h>
#include <stdint.h>

const char* get_dns_status_str(uint16_t flags) {
    uint8_t rcode = flags & 0x000F; 
    switch (rcode) {
        case 0:  return "NOERROR";
        case 1:  return "FORMERR";
        case 2:  return "SERVFAIL";
        case 3:  return "NXDOMAIN";
        case 4:  return "NOTIMP";
        case 5:  return "REFUSED";
        default: return "UNKNOWN_ERROR";
    }
}

int safe_parse_dns_name(const unsigned char *dns_start, 
                        const unsigned char *packet_end, 
                        const unsigned char *src, 
                        char *dst, int *dst_idx, 
                        int max_dst_len) {
    const unsigned char *ptr = src;
    int bytes_read = 0;
    int jumped = 0;
    int jump_count = 0; // ИСПРАВЛЕНО: Явный счетчик прыжков для защиты от петель

    while (ptr < packet_end) {
        if (jump_count > 10) return -1; // Защита от бесконечных циклов сжатия DNS

        uint8_t len = *ptr;

        // Встретили маркер конца DNS-имени
        if (len == 0) {
            if (!jumped) {
                bytes_read++; // Учитываем финальный нулевой байт в исходном потоке
            }
            ptr++;
            break;
        }

        // Обработка указателей сжатия DNS (0xC0)
        if ((len & 0xC0) == 0xC0) {
            if (ptr + 1 >= packet_end) return -1;
            
            int offset = ((len & 0x3F) << 8) | *(ptr + 1);
            
            // ИСПРАВЛЕНО:bytes_read фиксирует длину только ДО первого прыжка по памяти
            if (!jumped) { 
                bytes_read += 2; 
                jumped = 1; 
            }
            
            ptr = dns_start + offset;
            if (ptr >= packet_end || ptr < dns_start) return -1;
            jump_count++;
            continue; // Переходим к чтению по новому адресу
        }

        // Обработка обычной текстовой метки
        ptr++; 
        if (!jumped) {
            bytes_read++; // Учитываем байт длины метки
        }
        
        if (ptr + len > packet_end) return -1;
        
        // Копируем символы поддомена
        for (int i = 0; i < len; i++) {
            if (*dst_idx < max_dst_len - 1) {
                dst[(*dst_idx)++] = *ptr;
            }
            ptr++; 
            if (!jumped) {
                bytes_read++; // Учитываем каждый символ в исходном потоке
            }
        }

        // Если имя продолжается, аккуратно разделяем метки точкой
        if (ptr < packet_end && *ptr != 0) {
            if (*dst_idx < max_dst_len - 1) {
                dst[(*dst_idx)++] = '.';
            }
        }
    }
    
    dst[*dst_idx] = '\0';
    return bytes_read;
}
