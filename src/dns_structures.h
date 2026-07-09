#ifndef DNS_STRUCTURES_H
#define DNS_STRUCTURES_H

#include <time.h>
#include <stdint.h>

#define MAX_DNS_IDS 65536
#define IP_STR_LEN 16

struct dns_header {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

typedef struct {
    char name[256];
} target_domain_t;

typedef struct {
    char ip[IP_STR_LEN];
} dns_server_t;

typedef struct {
    char domain[256];
    char dns_server[IP_STR_LEN];
    time_t sent_time;
    int is_active;
} pending_request_t;

#endif
