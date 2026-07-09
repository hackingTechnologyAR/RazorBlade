



// parser.h

#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>

const char* get_dns_status_str(uint16_t flags);
int safe_parse_dns_name(const unsigned char *dns_start, 
                        const unsigned char *packet_end, 
                        const unsigned char *src, 
                        char *dst, int *dst_idx, 
                        int max_dst_len);

#endif


