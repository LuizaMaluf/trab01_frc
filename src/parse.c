#include "dns.h"

#include <string.h>

/* Le um inteiro de 16 bits em network byte order (big-endian). */
static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

int parse_header(const uint8_t *msg, size_t msglen, dns_header_t *hdr)
{
    if (msg == NULL || hdr == NULL || msglen < DNS_HEADER_LEN) {
        return -1;
    }

    /* RFC 1035 4.1.1: seis campos de 16 bits, nesta ordem. */
    hdr->id      = get_u16(msg + 0);
    hdr->flags   = get_u16(msg + 2);
    hdr->qdcount = get_u16(msg + 4);
    hdr->ancount = get_u16(msg + 6);
    hdr->nscount = get_u16(msg + 8);
    hdr->arcount = get_u16(msg + 10);

    return 0;
}

/* Limites da leitura de nomes (RFC 1035 2.3.4 e 4.1.4). */
#define LABEL_MAX_LEN     63      /* bytes de dados em um rotulo */
#define LABEL_TYPE_MASK   0xC0    /* 2 bits altos do byte de tamanho */
#define LABEL_POINTER     0xC0    /* 11xxxxxx: ponteiro de compressao */
#define POINTER_OFFSET_MASK 0x3F  /* 14 bits de offset = 6 bits + 1 byte */
#define MAX_LABELS        128     /* protecao extra contra nomes patologicos */

int read_name(const uint8_t *msg, size_t msglen, size_t offset,
              char *out, size_t outlen)
{
    size_t pos = offset;     /* cursor de leitura dentro de msg */
    size_t outpos = 0;       /* proximo byte livre em out */
    size_t consumed = 0;     /* bytes que o nome ocupa na posicao ORIGINAL */
    int jumped = 0;          /* ja seguiu um ponteiro? (congela 'consumed') */
    int labels = 0;

    if (msg == NULL || out == NULL || outlen == 0 || offset >= msglen) {
        return -1;
    }

    for (;;) {
        uint8_t len;

        if (pos >= msglen) {
            return -1;                      /* nome nao terminado dentro da mensagem */
        }
        len = msg[pos];

        if ((len & LABEL_TYPE_MASK) == LABEL_POINTER) {
            size_t target;

            if (pos + 1 >= msglen) {
                return -1;                  /* ponteiro truncado */
            }
            target = ((size_t)(len & POINTER_OFFSET_MASK) << 8) | msg[pos + 1];
            if (target >= pos) {
                return -1;                  /* so aponta para tras: impede ciclos */
            }
            if (!jumped) {
                consumed = pos + 2 - offset;
                jumped = 1;
            }
            pos = target;
            continue;
        }

        if ((len & LABEL_TYPE_MASK) != 0) {
            return -1;                      /* 01xxxxxx e 10xxxxxx sao reservados */
        }

        if (len == 0) {
            if (!jumped) {
                consumed = pos + 1 - offset;
            }
            if (outpos >= outlen) {
                return -1;
            }
            out[outpos] = '\0';
            return (int)consumed;
        }

        /* Rotulo comum: 1..63 bytes de dados logo apos o byte de tamanho. */
        if (len > LABEL_MAX_LEN || pos + 1 + len > msglen) {
            return -1;
        }
        if (++labels > MAX_LABELS) {
            return -1;
        }
        if (outpos > 0) {
            if (outpos + 1 >= outlen || outpos + 1 > DNS_MAX_WIRE_NAME) {
                return -1;
            }
            out[outpos++] = '.';
        }
        if (outpos + len >= outlen || outpos + len > DNS_MAX_WIRE_NAME) {
            return -1;                      /* precisa caber o rotulo e o '\0' */
        }
        memcpy(out + outpos, msg + pos + 1, len);
        outpos += len;
        pos += 1 + len;
    }
}

dns_status_t parse_response(const uint8_t *resp, size_t len,
                            mx_record_t *mx, int max_mx, int *count)
{
    dns_header_t hdr;

    *count = 0;

    /* Fase 7: header. Mensagem menor que 12 bytes nao e uma resposta. */
    if (parse_header(resp, len, &hdr) != 0) {
        return DNS_ERR_MALFORMED;
    }

    /* Fase 8: QR = 0 e uma consulta, nao uma resposta. */
    if (!DNS_FLAG_QR(hdr.flags)) {
        return DNS_ERR_MALFORMED;
    }

    /* Fase 8: o codigo de resposta decide antes de qualquer secao ser lida.
     * NXDOMAIN encerra aqui, sem tocar na autoridade. Qualquer outro erro do
     * servidor (SERVFAIL, REFUSED...) e falha de coleta. */
    switch (DNS_RCODE(hdr.flags)) {
    case DNS_RCODE_OK:
        break;
    case DNS_RCODE_NXDOMAIN:
        return DNS_ERR_NXDOMAIN;
    default:
        return DNS_ERR_MALFORMED;
    }

    /* TODO (Fases 10-11): pular QDCOUNT questions e percorrer ANCOUNT answers,
     * extraindo os registros MX em mx[0..max_mx-1]. Ate la, nenhum MX. */
    (void)mx; (void)max_mx;

    return DNS_ERR_NO_MX;
}
