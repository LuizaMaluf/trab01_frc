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

/* Flags da consulta fixadas pelo enunciado. */
#define DNS_FLAGS_QUERY    0x0100  /* QR=0, OPCODE=0, RD=1 */

/* Grava um inteiro de 16 bits em network byte order (big-endian). */
static void put_u16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)(value >> 8);
    buf[1] = (uint8_t)(value & 0xFF);
}

int build_query(uint8_t *buf, size_t buflen, const char *domain, uint16_t id)
{
    int name_len;
    size_t offset;

    if (buf == NULL || domain == NULL || buflen < DNS_HEADER_LEN) {
        return -1;
    }

    /* QNAME vai logo apos o header; encode_dns_name respeita o espaco restante. */
    name_len = encode_dns_name(domain, buf + DNS_HEADER_LEN, buflen - DNS_HEADER_LEN);
    if (name_len < 0) {
        return -1;
    }

    offset = DNS_HEADER_LEN + (size_t)name_len;
    if (buflen - offset < DNS_QUESTION_FIXED_LEN) {
        return -1;
    }

    /* Header: ID, flags, QDCOUNT=1, ANCOUNT/NSCOUNT/ARCOUNT=0. */
    put_u16(buf + 0, id);
    put_u16(buf + 2, DNS_FLAGS_QUERY);
    put_u16(buf + 4, 1);
    put_u16(buf + 6, 0);
    put_u16(buf + 8, 0);
    put_u16(buf + 10, 0);

    /* Question: QNAME ja gravado; QTYPE = MX, QCLASS = IN. */
    put_u16(buf + offset, DNS_TYPE_MX);
    put_u16(buf + offset + 2, DNS_CLASS_IN);

    return (int)(offset + DNS_QUESTION_FIXED_LEN);
}
