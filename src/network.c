





#include "network.h"
#include "parser.h"
#include "io_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

#define BUFFER_SIZE 65535
#define DNS_PORT 53
#define TIMEOUT_SEC 5

pending_request_t state_table[MAX_DNS_IDS];
int active_requests_count = 0;

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes == 1) { oddbyte = 0; *(u_char*)&oddbyte = *(u_char*)ptr; sum += oddbyte; }
    sum = (sum >> 16) + (sum & 0xffff); sum += (sum >> 16);
    answer = (short)~sum; return answer;
}

void check_packet_timeouts(void) {
    time_t now = time(NULL);
    for (int id = 0; id < MAX_DNS_IDS; id++) {
        if (state_table[id].is_active && (now - state_table[id].sent_time >= TIMEOUT_SEC)) {
            printf("[-] Таймаут: %s через %s\n", state_table[id].domain, state_table[id].dns_server);
            write_response_to_xml(state_table[id].domain, "TIMEOUT", NULL, NULL, 0, state_table[id].dns_server);
            state_table[id].is_active = 0;
            active_requests_count--;
        }
    }
}

int compress_domain(unsigned char *dns, const unsigned char *host) {
    unsigned char *dns_ptr = dns;
    const unsigned char *host_ptr = host;
    int label_len = 0;
    unsigned char *length_byte = dns_ptr++;
    while (1) {
        if (*host_ptr == '.' || *host_ptr == '\0') {
            *length_byte = label_len; label_len = 0; length_byte = dns_ptr;
            if (*host_ptr == '\0') break;
        } else { *dns_ptr = *host_ptr; label_len++; }
        dns_ptr++; host_ptr++;
    }
    *dns_ptr++ = 0x00; 
    *dns_ptr++ = 0x00; *dns_ptr++ = 0x10; // Type TXT (16)
    *dns_ptr++ = 0x00; *dns_ptr++ = 0x01; // Class IN (1)
    return (dns_ptr - dns);
}

uint16_t get_free_dns_id(void) {
    static uint16_t last_id = 0;
    for (int i = 0; i < MAX_DNS_IDS; i++) {
        last_id++;
        if (!state_table[last_id].is_active) return last_id;
    }
    return last_id;
}

void send_dynamic_fragmented_dns(int raw_sockfd, const char *src_ip, const char *dst_ip, const char *target_domain) {
    unsigned char dns_payload[BUFFER_SIZE];
    memset(dns_payload, 0, sizeof(dns_payload));
    uint16_t dns_id = get_free_dns_id();

    strncpy(state_table[dns_id].domain, target_domain, sizeof(state_table[dns_id].domain) - 1);
    strncpy(state_table[dns_id].dns_server, dst_ip, sizeof(state_table[dns_id].dns_server) - 1);
    state_table[dns_id].sent_time = time(NULL);
    state_table[dns_id].is_active = 1;
    active_requests_count++;

    struct dns_header *dns = (struct dns_header *)dns_payload;
    dns->id = htons(dns_id); dns->flags = htons(0x0100); dns->qdcount = htons(1); dns->arcount = htons(1);

    unsigned char *qname = dns_payload + sizeof(struct dns_header);
    int qname_len = compress_domain(qname, (const unsigned char*)target_domain);

    unsigned char *edns = qname + qname_len;
    memset(edns, 0, 11);
    edns[3] = 0x29; edns[4] = 0x10; // OPT RR EDNS0
    int dns_len = sizeof(struct dns_header) + qname_len + 11;

    char packet[BUFFER_SIZE];
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in sin;
    sin.sin_family = AF_INET; sin.sin_port = htons(DNS_PORT); sin.sin_addr.s_addr = inet_addr(dst_ip);
    uint16_t ip_id = rand() % 65535;

    int dns_header_and_query_len = sizeof(struct dns_header) + qname_len;
    int total_frag1_data = (sizeof(struct udphdr) + dns_header_and_query_len + 7) & ~7;
    int first_data_len = total_frag1_data - sizeof(struct udphdr);

    if (first_data_len > dns_len) {
        first_data_len = dns_len;
        total_frag1_data = sizeof(struct udphdr) + dns_len;
    }

    memset(packet, 0, sizeof(packet));
    udph->source = htons(31337); udph->dest = htons(DNS_PORT); udph->len = htons(sizeof(struct udphdr) + dns_len); udph->check = 0;
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), dns_payload, first_data_len);
    
    iph->ihl = 5; iph->version = 4; iph->tot_len = htons(sizeof(struct iphdr) + total_frag1_data);
    iph->id = htons(ip_id); iph->frag_off = htons(IP_MF | 0); iph->ttl = 64;
    iph->protocol = IPPROTO_UDP; iph->saddr = inet_addr(src_ip); iph->daddr = sin.sin_addr.s_addr;
    iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr));
    sendto(raw_sockfd, packet, sizeof(struct iphdr) + total_frag1_data, 0, (struct sockaddr *)&sin, sizeof(sin));

    int second_data_len = dns_len - first_data_len;
    if (second_data_len > 0) {
        memset(packet, 0, sizeof(packet));
        memcpy(packet + sizeof(struct iphdr), dns_payload + first_data_len, second_data_len);
        
        iph->ihl = 5; iph->version = 4; iph->tot_len = htons(sizeof(struct iphdr) + second_data_len);
        iph->id = htons(ip_id); 
        iph->frag_off = htons(total_frag1_data / 8); 
        iph->ttl = 64; iph->protocol = IPPROTO_UDP; iph->saddr = inet_addr(src_ip); iph->daddr = sin.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr));
        sendto(raw_sockfd, packet, sizeof(struct iphdr) + second_data_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }
}

void process_dns_packet(const u_char *packet, int packet_len) {
    const unsigned char *packet_end = packet + packet_len;
    if (packet_len < (int)sizeof(struct ether_header)) return;
    
    struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;
    
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));
    if ((unsigned char *)iph + sizeof(struct iphdr) > packet_end || iph->protocol != IPPROTO_UDP) return;
    
    int ip_hdr_len = iph->ihl * 4;
    struct in_addr responder_ip; responder_ip.s_addr = iph->saddr;
    char dns_server_ip[IP_STR_LEN];
    inet_ntop(AF_INET, &responder_ip, dns_server_ip, sizeof(dns_server_ip));
    
    struct udphdr *udph = (struct udphdr *)((char *)iph + ip_hdr_len);
    if ((unsigned char *)udph + sizeof(struct udphdr) > packet_end || ntohs(udph->uh_sport) != 53) return;
    
    const unsigned char *dns_start = (const unsigned char *)udph + sizeof(struct udphdr);
    if (dns_start + sizeof(struct dns_header) > packet_end) return;
    
    struct dns_header *dns = (struct dns_header *)dns_start;
    uint16_t flags = ntohs(dns->flags);
    if (!(flags & 0x8000)) return; 

    uint16_t dns_id = ntohs(dns->id);
    if (!state_table[dns_id].is_active) return;

    uint16_t qdcount = ntohs(dns->qdcount);
    uint16_t ancount = ntohs(dns->ancount);
    const char *dns_status = get_dns_status_str(flags);
    const unsigned char *reader = dns_start + sizeof(struct dns_header);
    char queried_domain[256] = {0};

    if (qdcount > 0) {
        int dst_idx = 0;
        int bytes_consumed = safe_parse_dns_name(dns_start, packet_end, reader, queried_domain, &dst_idx, sizeof(queried_domain));
        if (bytes_consumed < 0) return;
        reader += bytes_consumed + 4;
    }
    
    if ((flags & 0x000F) != 0) {
        printf("[-] Домен: %s | Статус: %s (от %s)\n", queried_domain, dns_status, dns_server_ip);
        write_response_to_xml(queried_domain, dns_status, NULL, NULL, 0, dns_server_ip);
        state_table[dns_id].is_active = 0; active_requests_count--;
        return;
    }
    if (ancount == 0) {
        printf("[*] Домен: %s | Статус: NOERROR_EMPTY (от %s)\n", queried_domain, dns_server_ip);
        write_response_to_xml(queried_domain, "NOERROR_EMPTY", NULL, NULL, 0, dns_server_ip);
        state_table[dns_id].is_active = 0; active_requests_count--;
        return;
    }

        for (int i = 0; i < ancount; i++) {
        char answer_name[256] = {0};
        int dst_idx = 0;
        int bytes_consumed = safe_parse_dns_name(dns_start, packet_end, reader, answer_name, &dst_idx, sizeof(answer_name));
        if (bytes_consumed < 0) return;
         
        reader += bytes_consumed;
        if (reader + 10 > packet_end) return;
           
        uint16_t type = ntohs(*(uint16_t *)reader); reader += 2;
        reader += 2; 
        uint32_t ttl = ntohl(*(uint32_t *)reader); reader += 4;
        uint16_t rdlen = ntohs(*(uint16_t *)reader); reader += 2;
         
        if (reader + rdlen > packet_end) return;
        
        if (type == 16) { 
            unsigned char txt_len = *reader;
            if (txt_len < rdlen) {
                char txt_str[256] = {0};
                size_t cpy_len = txt_len;
                memcpy(txt_str, reader + 1, cpy_len);
                printf("[+] Домен: %s -> TXT: %s (%s)\n", answer_name, txt_str, dns_status);
                write_response_to_xml(answer_name, dns_status, "TXT", txt_str, ttl, dns_server_ip);
                
                // Добавляем запись TXT в наш красивый HTML-отчет на Си
                write_response_to_html(answer_name, "TXT", txt_str, ttl);
            }
        } else if (type == 1 && rdlen == 4) { 
            struct in_addr ip_addr; memcpy(&ip_addr.s_addr, reader, 4);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_addr, ip_str, INET_ADDRSTRLEN);
            printf("[+] Домен: %s -> IP: %s (%s)\n", answer_name, ip_str, dns_status);
            write_response_to_xml(answer_name, dns_status, "A", ip_str, ttl, dns_server_ip);
            
            // Добавляем запись IP (A) в HTML-отчет
            write_response_to_html(answer_name, "A (IP)", ip_str, ttl);
        } else if (type == 5) { 
            char cname[256] = {0}; int cname_idx = 0;
            if (safe_parse_dns_name(dns_start, packet_end, reader, cname, &cname_idx, sizeof(cname)) >= 0) {
                printf("[+] Домен: %s -> CNAME: %s (%s)\n", answer_name, cname, dns_status);
                write_response_to_xml(answer_name, dns_status, "CNAME", cname, ttl, dns_server_ip);
                
                // Добавляем запись CNAME в HTML-отчет
                write_response_to_html(answer_name, "CNAME", cname, ttl);
            }
        } else {
            write_response_to_xml(answer_name, dns_status, "OTHER", "RAW_DATA", ttl, dns_server_ip);
        }
        reader += rdlen;
    }
     
    state_table[dns_id].is_active = 0; 
    active_requests_count--;
}

     
void handle_pcap_read(pcap_t *handle) {
	struct pcap_pkthdr *header;
	
	const u_char *packet;
	int res;int max_packets_per_run = 50;
	
	while (max_packets_per_run-- > 0 && (res = pcap_next_ex(handle, &header, &packet)) > 0) {
		process_dns_packet(packet, header->len);
		} 
		}












