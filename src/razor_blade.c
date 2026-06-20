
 /*
 * 
 * Async DNS Fragment Scanner
 * Copyright (C) 2026 Ваше Имя/Никнейм <ваш_email@example.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://gnu.org>.
 * 
 */
 
 /*
 * Copyright 2026 Unknown <ar@arch>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 */

// razor_blade.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/epoll.h>
#include <pcap.h>
#include <errno.h>
#include <time.h>

#define MAX_EVENTS 10
#define BUFFER_SIZE 65535
#define DNS_PORT 53
#define BATCH_SIZE 50
#define TIMEOUT_SEC 5
#define MAX_DNS_IDS 65536
#define XML_BUFFER_SIZE 65536
#define IP_STR_LEN 16

// Структуры данных для работы с сетью и DNS
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

// Глобальные переменные управления очередями и буферами
target_domain_t *target_list = NULL;
int total_targets = 0;
int current_send_index = 0;

dns_server_t *dns_pool = NULL;
int total_dns_servers = 0;
int current_dns_index = 0;

pending_request_t state_table[MAX_DNS_IDS];
FILE *global_xml_fd = NULL;
char xml_stream_buffer[XML_BUFFER_SIZE];

// Функция подсчета контрольной суммы IP-заголовка
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    return answer;
}

// Преобразование кодов ошибок DNS RCODE в понятный текст
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

// Чтение списка доменов-целей в оперативную память
int load_domains_from_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    int capacity = 1000;
    target_list = malloc(capacity * sizeof(target_domain_t));
    char line[256];

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0 || line[0] == '#') continue;

        if (total_targets >= capacity) {
            capacity *= 2;
            target_list = realloc(target_list, capacity * sizeof(target_domain_t));
        }
        strncpy(target_list[total_targets].name, line, sizeof(target_list[total_targets].name) - 1);
        total_targets++;
    }
    fclose(fp);
    return 0;
}

// Чтение пула DNS-серверов в оперативную память
int load_dns_pool_from_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    int capacity = 100;
    dns_pool = malloc(capacity * sizeof(dns_server_t));
    char line[256];

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0 || line[0] == '#') continue;

        if (total_dns_servers >= capacity) {
            capacity *= 2;
            dns_pool = realloc(dns_pool, capacity * sizeof(dns_server_t));
        }
        strncpy(dns_pool[total_dns_servers].ip, line, IP_STR_LEN - 1);
        dns_pool[total_dns_servers].ip[IP_STR_LEN - 1] = '\0';
        total_dns_servers++;
    }
    fclose(fp);
    return 0;
}

// Инициализация высокоскоростного файлового вывода
int init_global_xml(const char *filename) {
    global_xml_fd = fopen(filename, "w");
    if (!global_xml_fd) return -1;
    setvbuf(global_xml_fd, xml_stream_buffer, _IOFBF, XML_BUFFER_SIZE);
    fprintf(global_xml_fd, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<scan_records>\n");
    return 0;
}

// Потоковая неблокирующая запись в XML-буфер
void write_response_to_xml(const char *domain, const char *status, const char *rec_type, const char *value, uint32_t ttl, const char *dns_server_ip) {
    if (!global_xml_fd) return;
    long int timestamp = (long int)time(NULL);
    fprintf(global_xml_fd, "  <response>\n    <timestamp>%ld</timestamp>\n    <domain>%s</domain>\n    <dns_server>%s</dns_server>\n    <status>%s</status>\n", timestamp, domain, dns_server_ip, status);
    if (rec_type && value) {
        fprintf(global_xml_fd, "    <record>\n      <type>%s</type>\n      <value>%s</value>\n      <ttl>%u</ttl>\n    </record>\n", rec_type, value, ttl);
    }
    fprintf(global_xml_fd, "  </response>\n");
}

void close_global_xml() {
    if (global_xml_fd) {
        fprintf(global_xml_fd, "</scan_records>\n");
        fclose(global_xml_fd);
        global_xml_fd = NULL;
    }
}

// Посекундная проверка потерянных пакетов
void check_packet_timeouts() {
    time_t now = time(NULL);
    for (int id = 0; id < MAX_DNS_IDS; id++) {
        if (state_table[id].is_active && (now - state_table[id].sent_time >= TIMEOUT_SEC)) {
            printf("[-] Таймаут: %s через %s\n", state_table[id].domain, state_table[id].dns_server);
            write_response_to_xml(state_table[id].domain, "TIMEOUT", NULL, NULL, 0, state_table[id].dns_server);
            state_table[id].is_active = 0;
        }
    }
}

// Преобразование доменного имени в DNS-метки (длина + строка)
int compress_domain(unsigned char *dns, const unsigned char *host) {
    unsigned char *dns_ptr = dns;
    const unsigned char *host_ptr = host;
    int label_len = 0;
    unsigned char *length_byte = dns_ptr++;

    while (1) {
        if (*host_ptr == '.' || *host_ptr == '\0') {
            *length_byte = label_len;
            label_len = 0;
            length_byte = dns_ptr;
            if (*host_ptr == '\0') break;
        } else {
            *dns_ptr = *host_ptr;
            label_len++;
        }
        dns_ptr++; host_ptr++;
    }
    *dns_ptr++ = 0x00; // Конец меток
    *dns_ptr++ = 0x00; *dns_ptr++ = 0x01; // Type A (1)
    *dns_ptr++ = 0x00; *dns_ptr++ = 0x01; // Class IN (1)
    return (dns_ptr - dns);
}

// Сборка и отправка сырых фрагментированных IP-пакетов
void send_fragmented_dns(int raw_sockfd, const char *src_ip, const char *dst_ip, unsigned char *dns_payload, int dns_len) {
    char packet[BUFFER_SIZE];
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    uint16_t ip_id = rand() % 65535;

    // --- ФРАГМЕНТ 1: IP-заголовок + UDP-заголовок + 8 байт DNS данных ---
    int first_data_len = 8; 
    int fragment1_payload_len = sizeof(struct udphdr) + first_data_len;
    memset(packet, 0, sizeof(packet));
    
    udph->source = htons(31337);
    udph->dest = htons(DNS_PORT);
    udph->len = htons(sizeof(struct udphdr) + dns_len);
    udph->check = 0;
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), dns_payload, first_data_len);

    iph->ihl = 5; iph->version = 4; iph->tot_len = htons(sizeof(struct iphdr) + fragment1_payload_len);
    iph->id = htons(ip_id); iph->frag_off = htons(IP_MF | 0); iph->ttl = 64;
    iph->protocol = IPPROTO_UDP; iph->saddr = inet_addr(src_ip); iph->daddr = inet_addr(dst_ip);
    iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET; sin.sin_port = htons(DNS_PORT); sin.sin_addr.s_addr = iph->daddr;
    sendto(raw_sockfd, packet, sizeof(struct iphdr) + fragment1_payload_len, 0, (struct sockaddr *)&sin, sizeof(sin));

    // --- ФРАГМЕНТ 2: IP-заголовок + Остаток DNS данных (БЕЗ UDP) ---
    int second_data_len = dns_len - first_data_len;
    if (second_data_len > 0) {
        memset(packet, 0, sizeof(packet));
        memcpy(packet + sizeof(struct iphdr), dns_payload + first_data_len, second_data_len);

        iph->ihl = 5; iph->version = 4; iph->tot_len = htons(sizeof(struct iphdr) + second_data_len);
        iph->id = htons(ip_id); iph->frag_off = htons(0 | 2); // Смещение 16 байт / 8 = 2. MF = 0
        iph->ttl = 64; iph->protocol = IPPROTO_UDP; iph->saddr = inet_addr(src_ip); iph->daddr = inet_addr(dst_ip);
        iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr));
        sendto(raw_sockfd, packet, sizeof(struct iphdr) + second_data_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }
}

// Генерация свободного ID транзакции
uint16_t get_free_dns_id() {
    static uint16_t last_id = 0;
    for (int i = 0; i < MAX_DNS_IDS; i++) {
        last_id++;
        if (!state_table[last_id].is_active) return last_id;
    }
    return last_id;
}

// Построение структуры динамического DNS-запроса с EDNS0
void send_dynamic_fragmented_dns(int raw_sockfd, const char *src_ip, const char *dst_ip, const char *target_domain) {
    unsigned char dns_payload[BUFFER_SIZE];
    memset(dns_payload, 0, sizeof(dns_payload));
    uint16_t dns_id = get_free_dns_id();

    strncpy(state_table[dns_id].domain, target_domain, sizeof(state_table[dns_id].domain) - 1);
    strncpy(state_table[dns_id].dns_server, dst_ip, sizeof(state_table[dns_id].dns_server) - 1);
    state_table[dns_id].sent_time = time(NULL);
    state_table[dns_id].is_active = 1;

    struct dns_header *dns = (struct dns_header *)dns_payload;
    dns->id = htons(dns_id); dns->flags = htons(0x0100); dns->qdcount = htons(1); dns->arcount = htons(1);

    unsigned char *qname = dns_payload + sizeof(struct dns_header);
    int qname_len = compress_domain(qname, (const unsigned char*)target_domain);

    unsigned char *edns = qname + qname_len;
    edns[0] = 0x00; edns[1] = 0x00; edns[2] = 0x29; edns[3] = 0x10; edns[4] = 0x00; // OPT RR (EDNS0)
    int dns_len = sizeof(struct dns_header) + qname_len + 11;


    send_fragmented_dns(raw_sockfd, src_ip, dst_ip, dns_payload, dns_len);}

// Безопасный парсер DNS-имен с защитой от повреждения памяти
    int safe_parse_dns_name(const unsigned char *dns_start, 
                             const unsigned char *packet_end, 
                              const unsigned char *src, 
                               char *dst, int *dst_idx, 
                                int max_dst_len) {
	  const unsigned char *ptr = src;
	  
	  int bytes_read = 0, jumped = 0, safety_counter = 0;
	  
	  while (ptr < packet_end && *ptr != 0) {
		  if (safety_counter++ > 128) return -1;
		  if ((*ptr & 0xC0) == 0xC0) {
			  if (ptr + 1 >= packet_end) return -1;
			  
	  int offset = ((*ptr & 0x3F) << 8) | *(ptr + 1);
	  if (!jumped) { bytes_read += 2; jumped = 1; 
		  }
		  ptr = dns_start + offset;
		  if (ptr >= packet_end || ptr < dns_start) return -1;
		  } else {
			  int len = *ptr; ptr++;
			  if (!jumped) bytes_read++;
			  if (ptr + len > packet_end) return -1;
			  for (int i = 0; i < len; i++) {
				  if (*dst_idx < max_dst_len - 1) dst[(*dst_idx)++] = *ptr;ptr++; 
				  if (!jumped) bytes_read++;
				  }
				  if (ptr < packet_end && *ptr != 0 && *dst_idx < max_dst_len - 1) dst[(*dst_idx)++] = '.';
				  }}
				  if (!jumped) bytes_read++;dst[*dst_idx] = '\0';
				  
				  return bytes_read;
				  }
				  
// Глубокий разбор сетевых уровней (Ethernet -> IP -> UDP -> DNS)
void process_dns_packet(const u_char *packet, int packet_len) {
	const unsigned char *packet_end = packet + packet_len;
	if (packet_len < sizeof(struct ether_header)) 
	return;
	
	struct ether_header *eth = (struct ether_header *)packet;
	if (ntohs(eth->ether_type) != ETHERTYPE_IP) 
	return;
	
	struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));
	if ((unsigned char *)iph + sizeof(struct iphdr) > packet_end || iph->protocol != IPPROTO_UDP) 
	return;
	
	int ip_hdr_len = iph->ihl * 4;
	struct in_addr responder_ip; responder_ip.s_addr = iph->saddr;
	char dns_server_ip[IP_STR_LEN];strncpy(dns_server_ip, inet_ntoa(responder_ip), sizeof(dns_server_ip) - 1);
	
	struct udphdr *udph = (struct udphdr *)((char *)iph + ip_hdr_len);
	if ((unsigned char *)udph + sizeof(struct udphdr) > packet_end || ntohs(udph->uh_sport) != 53) 
	return;
	
	const unsigned char *dns_start = (const unsigned char *)udph + sizeof(struct udphdr);
	if (dns_start + sizeof(struct dns_header) > packet_end) 
	return;
	
	struct dns_header *dns = (struct dns_header *)dns_start;
	
	uint16_t flags = ntohs(dns->flags);if (!(flags & 0x8000)) return; 

	
// Пропускаем запросы
uint16_t dns_id = ntohs(dns->id);
if (state_table[dns_id].is_active) state_table[dns_id].is_active = 0; 
else return;

uint16_t qdcount = ntohs(dns->qdcount);
uint16_t ancount = ntohs(dns->ancount);

const char *dns_status = get_dns_status_str(flags);
const unsigned char *reader = dns_start + sizeof(struct dns_header);char queried_domain[256] = {0};

if (qdcount > 0) {
	int dst_idx = 0;
	int bytes_consumed = safe_parse_dns_name(dns_start, packet_end, reader, queried_domain, &dst_idx, sizeof(queried_domain));
	if (bytes_consumed < 0) return;
	reader += bytes_consumed + 4;
	}
	
// Логирование ошибок (NXDOMAIN, REFUSED и т.д.)

   if ((flags & 0x000F) != 0) {
	   printf("[-] Домен: %s | Статус: %s (от %s)\n", queried_domain, dns_status, dns_server_ip);
	   write_response_to_xml(queried_domain, dns_status, NULL, NULL, 0, dns_server_ip);
	   return;
	   }
	   if (ancount == 0) {printf("[*] Домен: %s | Статус: NOERROR_EMPTY (от %s)\n", 
		   queried_domain, dns_server_ip);write_response_to_xml(queried_domain, "NOERROR_EMPTY", NULL, NULL, 0, dns_server_ip);
		   return;
		   }


// Чтение записей ответов
   for (int i = 0; i < ancount; i++) {
	   char answer_name[256] = {0};
	   
	   int dst_idx = 0;
	   int bytes_consumed = safe_parse_dns_name(dns_start, packet_end, reader, answer_name, &dst_idx, sizeof(answer_name));
	     if (bytes_consumed < 0) 
	     return;
	     
       reader += bytes_consumed;
       if (reader + 10 > packet_end) return;
       
     uint16_t type = ntohs(*(uint16_t )reader); 
     reader += 2;
     uint16_t class = ntohs((uint16_t )reader); 
     reader += 2;
     uint32_t ttl = ntohl((uint32_t )reader); 
     reader += 4;
     uint16_t rdlen = ntohs((uint16_t *)reader); 
     reader += 2;
     
     if (reader + rdlen > packet_end) return;
     if (type == 1 && rdlen == 4) { // Запись A
		 
     struct in_addr ip_addr; memcpy(&ip_addr.s_addr, reader, 4);
     char *ip_str = inet_ntoa(ip_addr);
     
     printf("[+] Домен: %s -> IP: %s (%s)\n", answer_name, ip_str, dns_status);
     
     write_response_to_xml(answer_name, dns_status, "A", ip_str, ttl, dns_server_ip);
     } else if (type == 5) { // Запись CNAME
		 char cname[256] = {0}; 
		 int cname_idx = 0;
		 if (safe_parse_dns_name(dns_start, packet_end, reader, cname, &cname_idx, sizeof(cname)) >= 0) {
			 printf("[+] Домен: %s -> CNAME: %s (%s)\n", answer_name, cname, dns_status);
	
	write_response_to_xml(answer_name, dns_status, "CNAME", cname, ttl, dns_server_ip);}
	} else {
		write_response_to_xml(answer_name, dns_status, "OTHER", "RAW_DATA", ttl, dns_server_ip);}reader += rdlen;
		}
	}


// Чтение накопленных пакетов из неблокирующего pcap
void handle_pcap_read(pcap_t *handle) {
	struct pcap_pkthdr *header;
	
	const u_char *packet;
	int res;
	
	while ((res = pcap_next_ex(handle, &header, &packet)) > 0) {
		process_dns_packet(packet, header->len); 
		}
	}

		
// Главная управляющая функция
int main(int argc, char *argv[]) {
	srand(time(NULL));
	
// Ожидаем параметры, полученные автоматически из Bash-обертки
    if (argc < 3) {
		fprintf(stderr, "[-] Использование: %s <сетевой_интерфейс> <локальный_IP>\n", argv[0]);
		
		return 1;
		}
		
		const char *iface = argv[1];
		const char *my_ip = argv[2];
		   if (load_domains_from_file("domains.txt") < 0 || total_targets == 0) {fprintf(stderr, "[-] Ошибка: файл domains.txt пуст или отсутствует\n");
			   return 1;
			   }
		   if (load_dns_pool_from_file("resolvers.txt") < 0 || total_dns_servers == 0) {
			   fprintf(stderr, "[-] Ошибка: файл resolvers.txt пуст или отсутствует\n");
			   free(target_list); 
			   return 1;
			   }
		   if (init_global_xml("scan_results.xml") < 0) {
			   free(target_list); free(dns_pool); 
			   return 1;
			   }

int raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

int one = 1;setsockopt(raw_sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

char errbuf[PCAP_ERRBUF_SIZE];pcap_t *pcap_handle = pcap_open_live(iface, 65535, 1, 1, errbuf);
          if (!pcap_handle) {fprintf(stderr, "[-] Ошибка pcap: %s\n", errbuf);
			  close_global_xml(); 
			  close(raw_sockfd); 
			  
			  free(target_list); 
			  free(dns_pool);
			  
			  return 1;
			  }
			  
			  pcap_setnonblock(pcap_handle, 1, errbuf);
			  
int pcap_fd = pcap_get_selectable_fd(pcap_handle);
int epoll_fd = epoll_create1(0);

struct epoll_event ev, events[MAX_EVENTS];ev.events = EPOLLIN | EPOLLET; ev.data.fd = pcap_fd;epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pcap_fd, &ev);

time_t last_timeout_check = time(NULL);

int scan_finished = 0;
memset(state_table, 0, sizeof(state_table));printf("[] Высокоскоростной асинхронный скан запущен.\n");

printf("[] Интерфейс: %s | Локальный IP: %s\n", iface, my_ip);
printf("[*] Загружено доменов: %d | Резолверов в пуле: %d\n", total_targets, total_dns_servers);
printf("------------------------------------------------------------\n");

while (!scan_finished) {
	int sent_in_this_batch = 0;
	
// Генерация сетевой нагрузки порциями (батчами)
while (current_send_index < total_targets && sent_in_this_batch < BATCH_SIZE) {
	send_dynamic_fragmented_dns(raw_sockfd, my_ip, dns_pool[current_dns_index].ip, target_list[current_send_index].name);
	current_dns_index = (current_dns_index + 1) % total_dns_servers;current_send_index++; 
	sent_in_this_batch++;
	}
// Проверка таймаутов раз в 1 секунду
time_t now = time(NULL);
if (now - last_timeout_check >= 1) {
	check_packet_timeouts();last_timeout_check = now;
	}
	
	int active_requests_count = 0;
	  for (int i = 0; i < MAX_DNS_IDS; i++) { 
		  if (state_table[i].is_active) active_requests_count++; 
		  }

// Если все цели отправлены и в таблице состояний пусто — выходим
if (current_send_index >= total_targets && active_requests_count == 0) {scan_finished = 1; 
	break;}
	
// Неблокирующее ожидание ответов
int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 10);
  if (nfds < 0 && errno != EINTR) 
  break;
  
  for (int i = 0; i < nfds; i++) {
	  if (events[i].data.fd == pcap_fd) handle_pcap_read(pcap_handle);
	  }
	 }
	 close_global_xml();
	 close(epoll_fd); 
	 pcap_close(pcap_handle); 
	 close(raw_sockfd);free(target_list); 
	 
	 free(dns_pool);
	 
	 printf("------------------------------------------------------------\n");
	 printf("[+] Сканирование завершено. Результаты в 'scan_results.xml'.\n");
	 
	 return 0;
}
    
    
    


    
    
    

    
    
    
    
    
    
    

