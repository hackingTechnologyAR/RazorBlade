



// Шаг 3: Сетевой модуль (Низкоуровневая отправка и фрагментация)

// network.h

#ifndef NETWORK_H
#define NETWORK_H

#include "dns_structures.h"
#include <pcap.h>

// Гарантируем, что размер таблицы в объявлении строго равен 65536
#define ACTUAL_MAX_IDS 65536

// Используем ACTUAL_MAX_IDS для точной синхронизации с network.c
extern pending_request_t state_table[ACTUAL_MAX_IDS];
extern int active_requests_count; // Глобальный счетчик вместо тяжелого цикла

void check_packet_timeouts(void);
void send_dynamic_fragmented_dns(int raw_sockfd, const char *src_ip, const char *dst_ip, const char *target_domain);
void process_dns_packet(const u_char *packet, int packet_len);
void handle_pcap_read(pcap_t *handle);

#endif

