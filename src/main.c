


// Шаг 5: Ядро программы (main.c)

// main.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <errno.h>
#include "dns_structures.h"
#include "io_utils.h"
#include "network.h"

#define MAX_EVENTS 10
#define BATCH_SIZE 50

int main(int argc, char *argv[]) {
    srand(time(NULL));
	
    if (argc < 3) {
        fprintf(stderr, "[-] Использование: %s <сетевой_интерфейс> <локальный_IP>\n", argv[0]);
        return 1;
    }
		
    const char *iface = argv[1];
    const char *my_ip = argv[2];

    if (load_domains_from_file("domains.txt") < 0 || total_targets == 0) {
        fprintf(stderr, "[-] Ошибка: файл domains.txt пуст или отсутствует\n");
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
    int one = 1;
    setsockopt(raw_sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_live(iface, 65535, 1, 1, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "[-] Ошибка pcap: %s\n", errbuf);
        close_global_xml(); close(raw_sockfd); free(target_list); free(dns_pool);
        return 1;
    }
			  
    pcap_setnonblock(pcap_handle, 1, errbuf);
			  
    int pcap_fd = pcap_get_selectable_fd(pcap_handle);
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        fprintf(stderr, "[-] Ошибка epoll_create1\n");
        pcap_close(pcap_handle); close(raw_sockfd); free(target_list); free(dns_pool);
        return 1;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN; // Исправлено: удален опасный EPOLLET
    ev.data.fd = pcap_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pcap_fd, &ev);

    time_t last_timeout_check = time(NULL);
    int scan_finished = 0;
    memset(state_table, 0, sizeof(state_table));

    printf("[] Высокоскоростной асинхронный скан запущен.\n");
    printf("[] Интерфейс: %s | Локальный IP: %s\n", iface, my_ip);
    printf("[*] Загружено доменов: %d | Резолверов в пуле: %d\n", total_targets, total_dns_servers);
    printf("------------------------------------------------------------\n");

    while (!scan_finished) {
        int sent_in_this_batch = 0;
	
        while (current_send_index < total_targets && sent_in_this_batch < BATCH_SIZE) {
            send_dynamic_fragmented_dns(raw_sockfd, my_ip, dns_pool[current_dns_index].ip, target_list[current_send_index].name);
            current_dns_index = (current_dns_index + 1) % total_dns_servers;
            current_send_index++; 
            sent_in_this_batch++;
        }

        time_t now = time(NULL);
        if (now - last_timeout_check >= 1) {
            check_packet_timeouts();
            last_timeout_check = now;
        }
	
        // Тяжелый цикл вырезан! Используем быструю переменную active_requests_count
        if (current_send_index >= total_targets && active_requests_count == 0) {
            scan_finished = 1; 
            break;
        }
	
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 10);
        if (nfds < 0 && errno != EINTR) break;
  
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == pcap_fd) {
                handle_pcap_read(pcap_handle);
            }
        }
    }

    close_global_xml();
    close(epoll_fd); 
    pcap_close(pcap_handle); 
    close(raw_sockfd);
    free(target_list); 
    free(dns_pool);
	 
    printf("------------------------------------------------------------\n");
    printf("[+] Сканирование завершено. Результаты в 'scan_results.xml'.\n");
	 
    return 0;
}
