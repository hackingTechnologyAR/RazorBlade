
// main.c — Модернизированное ядро высокоскоростного асинхронного сканера RazorBlade

// sudo ./razorblade enp6s0 192.168.1.69

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h> // Обязательный заголовок для работы с временем
#include <sys/socket.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pcap.h>
#include "dns_structures.h"
#include "io_utils.h"
#include "network.h"

#define MAX_EVENTS 10
#define MAX_ACTIVE_REQUESTS 2000 

int main(int argc, char *argv[]) {

    srand(time(NULL));
	
    if (argc < 3) {
        fprintf(stderr, "[-] Использование: %s <сетевой_интерфейс> <локальный_IP>\n", argv[0]);
        return 1;
    }
		
    const char *iface = argv[1];
    const char *my_ip = argv[2];

    // Инициализируем дескрипторы дефолтными значениями для безопасной очистки в cleanup
    int raw_sockfd = -1;
    int epoll_fd = -1;
    pcap_t *pcap_handle = NULL;
    int exit_status = 0;

    // Загрузка словарей и доменов
    if (load_domains_from_file("domains.txt") < 0 || total_targets == 0) {
        fprintf(stderr, "[-] Ошибка: файл domains.txt пуст или отсутствует\n");
        return 1;
    }
    if (load_dns_pool_from_file("resolvers.txt") < 0 || total_dns_servers == 0) {
        fprintf(stderr, "[-] Ошибка: файл resolvers.txt пуст или отсутствует\n");
        exit_status = 1;
        goto cleanup;
    }
    if (init_global_xml("scan_results.xml") < 0) {
        fprintf(stderr, "[-] Ошибка инициализации scan_results.xml\n");
        exit_status = 1;
        goto cleanup;
    }
    if (init_global_html("scan_report.html") < 0) {
        fprintf(stderr, "[-] Ошибка инициализации scan_report.html\n");
        exit_status = 1;
        goto cleanup;
    }

    // Создание сырого сокета с обязательной валидацией дескриптора (защита от запуска без sudo)
    raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sockfd < 0) {
        fprintf(stderr, "[-] Ошибка создания сырого сокета! Запустите программу от root (sudo).\n");
        exit_status = 1;
        goto cleanup;
    }
    int one = 1;
    setsockopt(raw_sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    // Инициализация PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(iface, 65535, 1, 1, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "[-] Ошибка pcap: %s\n", errbuf);
        exit_status = 1;
        goto cleanup;
    }
			  
    pcap_setnonblock(pcap_handle, 1, errbuf);
			  
    int pcap_fd = pcap_get_selectable_fd(pcap_handle);
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        fprintf(stderr, "[-] Ошибка epoll_create1\n");
        exit_status = 1;
        goto cleanup;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN; 
    ev.data.fd = pcap_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pcap_fd, &ev) < 0) {
        fprintf(stderr, "[-] Ошибка epoll_ctl\n");
        exit_status = 1;
        goto cleanup;
    }

    time_t last_timeout_check = time(NULL);
    int scan_finished = 0;
    memset(state_table, 0, sizeof(state_table));

    printf("[] Высокоскоростной асинхронный скан RazorBlade запущен.\n");
    printf("[] Интерфейс: %s | Локальный IP: %s\n", iface, my_ip);
    printf("[*] Загружено доменов: %d | Резолверов в пуле: %d\n", total_targets, total_dns_servers);
    printf("------------------------------------------------------------\n");

    while (!scan_finished) {
        int sent_this_turn = 0;
	
        // УЛУЧШЕНО: Шлем пакеты непрерывно, пока позволяет лимит active_requests_count
        while (current_send_index < total_targets && active_requests_count < MAX_ACTIVE_REQUESTS) {
            send_dynamic_fragmented_dns(raw_sockfd, my_ip, dns_pool[current_dns_index].ip, target_list[current_send_index].name);
            current_dns_index = (current_dns_index + 1) % total_dns_servers;
            current_send_index++; 
            sent_this_turn++;
            
            // Защита: прерываем пачку отправки, чтобы дать epoll обработать ответы и не забивать буфер
            if (sent_this_turn >= 200) break;
        }

        // Проверка таймаутов раз в секунду
        time_t now = time(NULL);
        if (now - last_timeout_check >= 1) {
            check_packet_timeouts();
            last_timeout_check = now;
        }
	
        // Безопасное условие завершения: отправили всё и дождались обработки всех активных запросов
        if (current_send_index >= total_targets && active_requests_count == 0) {
            scan_finished = 1; 
            break;
        }
	
        // УЛУЧШЕНО: Снизили таймаут до 2 мс для мгновенного сбора ответов на лету
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 2);
        if (nfds < 0 && errno != EINTR) break;
  
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == pcap_fd) {
                // Наш агрессивный обработчик pcap выкачивает буфер
                handle_pcap_read(pcap_handle);
            }
        }
    }

    printf("------------------------------------------------------------\n");
    printf("[+] Сканирование завершено. Результаты в 'scan_results.xml' и 'scan_report.html'.\n");

cleanup:
    // Единый канонический блок безопасного освобождения ресурсов
    close_global_html();
    close_global_xml();
    if (epoll_fd >= 0) close(epoll_fd); 
    if (pcap_handle) pcap_close(pcap_handle); 
    if (raw_sockfd >= 0) close(raw_sockfd);
    if (target_list) free(target_list); 
    if (dns_pool) free(dns_pool);
	 
    return exit_status;
}
