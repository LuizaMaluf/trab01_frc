#include "dns.h"

#include <string.h>

int encode_dns_name(const char *domain, uint8_t *buf, size_t buflen)
{
    size_t domain_len;
    size_t label_start = 0;
    size_t encoded_len = 1; /* byte 0 que encerra o nome */
    size_t output_pos = 0;

    if (domain == NULL || buf == NULL) {
        return -1;
    }

    domain_len = strlen(domain);
    if (domain_len == 0) {
        return -1;
    }

    /* Primeira passagem: valida os rotulos e calcula o tamanho necessario. */
    for (size_t i = 0; i <= domain_len; i++) {
        if (domain[i] == '.' || domain[i] == '\0') {
            size_t label_len = i - label_start;

            if (label_len == 0 || label_len > 63) {
                return -1;
            }

            encoded_len += 1 + label_len;
            if (encoded_len > DNS_MAX_WIRE_NAME) {
                return -1;
            }

            label_start = i + 1;
        }
    }

    if (encoded_len > buflen) {
        return -1;
    }

    /* Segunda passagem: grava tamanho + conteudo de cada rotulo. */
    label_start = 0;
    for (size_t i = 0; i <= domain_len; i++) {
        if (domain[i] == '.' || domain[i] == '\0') {
            size_t label_len = i - label_start;

            buf[output_pos++] = (uint8_t)label_len;
            memcpy(buf + output_pos, domain + label_start, label_len);
            output_pos += label_len;
            label_start = i + 1;
        }
    }

    buf[output_pos++] = 0;
    return (int)output_pos;
}

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
