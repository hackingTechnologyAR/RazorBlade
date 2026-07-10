#ifndef IO_UTILS_H
#define IO_UTILS_H

#include "dns_structures.h"
#include <stdint.h>

extern target_domain_t *target_list;
extern int total_targets;
extern int current_send_index;

extern dns_server_t *dns_pool;
extern int total_dns_servers;
extern int current_dns_index;

int load_domains_from_file(const char *filename);
int load_dns_pool_from_file(const char *filename);
int init_global_xml(const char *filename);
void write_response_to_xml(const char *domain, const char *status, const char *rec_type, const char *value, uint32_t ttl, const char *dns_server_ip);
void close_global_xml(void);

int init_global_html(const char *filename);
void write_response_to_html(const char *domain, const char *rec_type, const char *value, uint32_t ttl);
void close_global_html(void);

#endif
