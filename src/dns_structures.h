



#ifndef DNS_STRUCTURES_H
#define DNS_STRUCTURES_H

#include <time.h>
#include <stdint.h>

#define MAX_DNS_IDS 65536
// ИСПРАВЛЕНО: Расширили до 46 байт для поддержки любых IP и устранения варнингов компилятора
#define IP_STR_LEN 46 

// Бинарный заголовок DNS согласно RFC 1035
struct dns_header {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

typedef struct {
    // ИСПРАВЛЕНО: Увеличили до 512 для безопасного добавления префикса "_dmarc."
    char name[512]; 
} target_domain_t;

typedef struct {
    char ip[IP_STR_LEN];
} dns_server_t;

typedef struct {
    // ИСПРАВЛЕНО: Синхронизировали размер с target_domain_t
    char domain[512]; 
    char dns_server[IP_STR_LEN];
    time_t sent_time;
    int is_active;
} pending_request_t;

#endif
