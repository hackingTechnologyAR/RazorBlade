


// parser.c

#include "parser.h"
#include <string.h>

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
            if (!jumped) { 
                bytes_read += 2; 
                jumped = 1; 
            }
            ptr = dns_start + offset;
            if (ptr >= packet_end || ptr < dns_start) return -1;
        } else {
            int len = *ptr; 
            ptr++;
            
            if (!jumped) bytes_read++; 
            if (ptr + len > packet_end) return -1;
            
            for (int i = 0; i < len; i++) {
                if (*dst_idx < max_dst_len - 1) {
                    dst[(*dst_idx)++] = *ptr;
                }
                ptr++; 
            }
            if (!jumped) bytes_read += len; 

            if (ptr < packet_end && *ptr != 0 && *dst_idx < max_dst_len - 1) {
                dst[(*dst_idx)++] = '.';
            }
        }
    }
    
    if (!jumped) {
        bytes_read++; 
    }
    
    dst[*dst_idx] = '\0';
    return bytes_read;
}


