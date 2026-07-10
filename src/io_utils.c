



#include "io_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

target_domain_t *target_list = NULL;
int total_targets = 0;
int current_send_index = 0;

dns_server_t *dns_pool = NULL;
int total_dns_servers = 0;
int current_dns_index = 0;

FILE *global_xml_fd = NULL;
#define XML_BUFFER_SIZE 65536
char xml_stream_buffer[XML_BUFFER_SIZE];

int load_domains_from_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    int capacity = 1000;
    target_list = malloc(capacity * sizeof(target_domain_t));
    char line[240];  // // Уменьшили размер буфера, чтобы убрать предупреждение о truncate

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0 || line[0] == '#') continue;

        if (total_targets >= capacity) {
            capacity *= 2;
            target_domain_t *tmp = realloc(target_list, capacity * sizeof(target_domain_t));
            if (!tmp) { fclose(fp); return -1; }
            target_list = tmp;
        }

        // Автоматическая подстановка префикса _dmarc. если пользователь его забыл
        if (strncmp(line, "_dmarc.", 7) != 0) {
            snprintf(target_list[total_targets].name, sizeof(target_list[total_targets].name), "_dmarc.%s", line);
        } else {
            snprintf(target_list[total_targets].name, sizeof(target_list[total_targets].name), "%s", line);
        }

        total_targets++;
    }
    fclose(fp);
    return 0;
}

int load_dns_pool_from_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    int capacity = 100;
    dns_pool = malloc(capacity * sizeof(dns_server_t));
    char line[IP_STR_LEN]; // Буфер ограничен IP_STR_LEN для исключения варнингов

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0 || line[0] == '#') continue;

        if (total_dns_servers >= capacity) {
            capacity *= 2;
            dns_server_t *tmp = realloc(dns_pool, capacity * sizeof(dns_server_t));
            if (!tmp) { fclose(fp); return -1; }
            dns_pool = tmp;
        }
        snprintf(dns_pool[total_dns_servers].ip, sizeof(dns_pool[total_dns_servers].ip), "%s", line);
        total_dns_servers++;
    }
    fclose(fp);
    return 0;
}

int init_global_xml(const char *filename) {
    global_xml_fd = fopen(filename, "w");
    if (!global_xml_fd) return -1;
    setvbuf(global_xml_fd, xml_stream_buffer, _IOFBF, XML_BUFFER_SIZE);
    fprintf(global_xml_fd, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<scan_records>\n");
    return 0;
}

void write_response_to_xml(const char *domain, const char *status, const char *rec_type, const char *value, uint32_t ttl, const char *dns_server_ip) {
    if (!global_xml_fd) return;
    long int timestamp = (long int)time(NULL);
    fprintf(global_xml_fd, "  <response>\n    <timestamp>%ld</timestamp>\n    <domain>%s</domain>\n    <dns_server>%s</dns_server>\n    <status>%s</status>\n", timestamp, domain, dns_server_ip, status);
    if (rec_type && value) {
        fprintf(global_xml_fd, "    <record>\n      <type>%s</type>\n      <value>%s</value>\n      <ttl>%u</ttl>\n    </record>\n", rec_type, value, ttl);
    }
    fprintf(global_xml_fd, "  </response>\n");
}

void close_global_xml(void) {
    if (global_xml_fd) {
        fprintf(global_xml_fd, "</scan_records>\n");
        fclose(global_xml_fd);
        global_xml_fd = NULL;
    }
}
