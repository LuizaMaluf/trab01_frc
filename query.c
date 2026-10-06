#include "dns.h"

int build_query(uint8_t *buf, size_t buflen, const char *domain, uint16_t id)
{
    /* TODO (Pessoa 1):
     * - header: ID, flags 0x0100, QDCOUNT 1, AN/NS/ARCOUNT 0 (network byte order)
     * - QNAME: "unb.br" -> 03 'u' 'n' 'b' 02 'b' 'r' 00
     * - QTYPE = DNS_TYPE_MX, QCLASS = DNS_CLASS_IN
     * - checar buflen e rotulos > 63 bytes */
    (void)buf; (void)buflen; (void)domain; (void)id;
    return -1;
}
