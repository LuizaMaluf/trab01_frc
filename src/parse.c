#include "dns.h"

int read_name(const uint8_t *msg, size_t msglen, size_t offset,
              char *out, size_t outlen)
{
    /* TODO (Pessoa 3):
     * - rotulo normal: byte de tamanho (0..63) + bytes
     * - ponteiro: 2 bits altos = 11 -> offset de 14 bits
     * - 0x00 encerra o nome
     * - proteger contra loop de ponteiros e leitura fora de msglen */
    (void)msg; (void)msglen; (void)offset; (void)out; (void)outlen;
    return -1;
}

dns_status_t parse_response(const uint8_t *resp, size_t len,
                            mx_record_t *mx, int max_mx, int *count)
{
    /* TODO (Pessoa 3):
     * - len >= 12; checar bit QR e RCODE (flags & 0x000F): 3 -> NXDOMAIN
     * - pular QDCOUNT questions (nome + 4 bytes)
     * - para cada answer: nome, TYPE, CLASS, TTL, RDLENGTH, RDATA
     *   se TYPE == DNS_TYPE_MX: preference (2 bytes) + read_name
     * - nenhum MX -> DNS_ERR_NO_MX */
    (void)resp; (void)len; (void)mx; (void)max_mx;
    *count = 0;
    return DNS_ERR_MALFORMED;
}
