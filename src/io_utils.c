



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

FILE *global_html_fd = NULL;

int init_global_html(const char *filename) {
    global_html_fd = fopen(filename, "w");
    if (!global_html_fd) return -1;

    // Пишем красивую шапку веб-страницы со стилями прямо через Си!
    fprintf(global_html_fd, 
        "<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n<meta charset=\"UTF-8\">\n"
        "<title>RazorBlade - Си Отчет Почтового Аудита</title>\n"
        "<style>\n"
        "  body { background: #1e1e2e; color: #cdd6f4; font-family: sans-serif; padding: 30px; }\n"
        "  .container { max-width: 1200px; margin: 0 auto; }\n"
        "  h1 { color: #cba6f7; border-bottom: 2px solid #252538; padding-bottom: 10px; }\n"
        "  .card { background: #252538; padding: 20px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }\n"
        "  .domain-title { font-size: 1.4rem; font-weight: bold; color: #fff; margin-bottom: 15px; }\n"
        "  .grid { display: flex; gap: 20px; }\n"
        "  .box { flex: 1; background: rgba(255,255,255,0.03); padding: 15px; border-radius: 8px; border-left: 4px solid #cba6f7; }\n"
        "  .box-title { font-weight: bold; color: #cba6f7; margin-bottom: 8px; text-transform: uppercase; font-size: 0.85rem; }\n"
        "  .raw { background: #11111b; padding: 8px; border-radius: 4px; color: #fab387; font-family: monospace; font-size: 0.85rem; word-break: break-all; }\n"
        "</style>\n</head>\n<body>\n<div class=\"container\">\n<h1>📊 RazorBlade — Результаты Асинхронного Аудита (Язык Си)</h1>\n"
    );
    return 0;
}

void write_response_to_html(const char *domain, const char *rec_type, const char *value, uint32_t ttl) {
    if (!global_html_fd) return;
    fprintf(global_html_fd, 
        "<div class=\"card\">\n"
        "  <div class=\"domain-title\">🌐 %s</div>\n"
        "  <div class=\"grid\">\n"
        "    <div class=\"box\">\n"
        "      <div class=\"box-title\">Тип записи: %s (TTL: %u)</div>\n"
        "      <div class=\"raw\">%s</div>\n"
        "    </div>\n"
        "  </div>\n"
        "</div>\n", 
        domain, rec_type, ttl, value
    );
}

void close_global_html(void) {
    if (global_html_fd) {
        fprintf(global_html_fd, "</div>\n</body>\n</html>\n");
        fclose(global_html_fd);
        global_html_fd = NULL;
    }
}


























