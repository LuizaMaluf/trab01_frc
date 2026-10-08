#include "dns.h"

#include <string.h>

/* Le um inteiro de 16 bits em network byte order (big-endian). */
static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Le um inteiro de 32 bits em network byte order (usado no TTL). */
static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
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

/* ---------- Fase 10: percorrer os Resource Records ---------- */

int skip_questions(const uint8_t *msg, size_t msglen, size_t offset, uint16_t qdcount)
{
    char name[DNS_MAX_NAME];    /* o nome so e lido para validar e medir */
    size_t pos = offset;

    if (msg == NULL) {
        return -1;
    }

    for (uint16_t i = 0; i < qdcount; i++) {
        int name_len = read_name(msg, msglen, pos, name, sizeof(name));

        if (name_len < 0) {
            return -1;
        }
        pos += (size_t)name_len;

        /* Depois do nome vem QTYPE e QCLASS, 2 bytes cada. */
        if (msglen - pos < DNS_QUESTION_FIXED_LEN) {
            return -1;
        }
        pos += DNS_QUESTION_FIXED_LEN;
    }

    return (int)pos;
}

int parse_rr(const uint8_t *msg, size_t msglen, size_t offset, dns_rr_t *rr)
{
    char name[DNS_MAX_NAME];
    size_t pos;
    int name_len;

    if (msg == NULL || rr == NULL) {
        return -1;
    }

    /* NAME: normalmente C0 0C (ponteiro para o nome da question). */
    name_len = read_name(msg, msglen, offset, name, sizeof(name));
    if (name_len < 0) {
        return -1;
    }
    pos = offset + (size_t)name_len;       /* read_name garante pos <= msglen */

    /* TYPE, CLASS, TTL e RDLENGTH: 10 bytes fixos logo depois do nome. */
    if (msglen - pos < DNS_RR_FIXED_LEN) {
        return -1;
    }
    rr->type     = get_u16(msg + pos);
    rr->rrclass  = get_u16(msg + pos + 2);
    rr->ttl      = get_u32(msg + pos + 4);
    rr->rdlength = get_u16(msg + pos + 8);
    pos += DNS_RR_FIXED_LEN;

    /* RDATA: precisa caber inteiro no que sobrou da mensagem. */
    if (rr->rdlength > msglen - pos) {
        return -1;
    }
    rr->rdata_offset = pos;

    return (int)(pos + rr->rdlength - offset);
}

int parse_answers(const uint8_t *msg, size_t msglen,
                  dns_rr_t *rrs, int max_rrs, int *count)
{
    dns_header_t hdr;
    int pos;
    int stored = 0;

    if (count == NULL) {
        return -1;
    }
    *count = 0;

    if (rrs == NULL || max_rrs < 0 || parse_header(msg, msglen, &hdr) != 0) {
        return -1;
    }

    /* As answers comecam depois do header e das questions. */
    pos = skip_questions(msg, msglen, DNS_HEADER_LEN, hdr.qdcount);
    if (pos < 0) {
        return -1;
    }

    for (uint16_t i = 0; i < hdr.ancount; i++) {
        dns_rr_t rr;
        int used = parse_rr(msg, msglen, (size_t)pos, &rr);

        if (used < 0) {
            return -1;
        }
        if (stored < max_rrs) {
            rrs[stored++] = rr;
        }
        pos += used;
    }

    *count = stored;
    return 0;
}

/* ---------- Fase 11: extrair o MX ---------- */

/* RDATA de um MX (RFC 1035 3.3.9): PREFERENCE (2 bytes) + EXCHANGE (nome).
 * O menor RDATA valido tem a preference e o nome raiz (um unico byte 00). */
#define MX_PREFERENCE_LEN 2
#define MX_MIN_RDLENGTH   (MX_PREFERENCE_LEN + 1)

/* Interpreta o RDATA de rr (que deve ser TYPE MX) e preenche *out.
 * Retorna 0 ou -1 se o RDATA for curto demais ou o nome sair do RDATA. */
static int parse_mx_rdata(const uint8_t *msg, size_t msglen, const dns_rr_t *rr,
                          mx_record_t *out)
{
    int name_len;

    if (rr->rdlength < MX_MIN_RDLENGTH) {
        return -1;
    }

    out->preference = get_u16(msg + rr->rdata_offset);

    /* O nome pode usar ponteiro de compressao (ex.: C0 0C), por isso e lido
     * dentro da mensagem inteira e nao apenas dentro do RDATA. */
    name_len = read_name(msg, msglen, rr->rdata_offset + MX_PREFERENCE_LEN,
                         out->exchange, sizeof(out->exchange));
    if (name_len < 0) {
        return -1;
    }

    /* O nome, na posicao original, tem que terminar dentro do RDATA: senao o
     * RDLENGTH mente sobre onde o registro acaba. */
    if ((size_t)name_len > (size_t)rr->rdlength - MX_PREFERENCE_LEN) {
        return -1;
    }

    return 0;
}

dns_status_t parse_response(const uint8_t *resp, size_t len,
                            mx_record_t *mx, int max_mx, int *count)
{
    dns_header_t hdr;
    dns_rr_t rrs[DNS_MAX_RR];
    int nrr;
    int found = 0;

    if (count == NULL) {
        return DNS_ERR_MALFORMED;
    }
    *count = 0;

    if (mx == NULL || max_mx < 0) {
        return DNS_ERR_MALFORMED;
    }

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

    /* Fase 10: pula as questions e percorre as answers. Uma mensagem cortada
     * ou com registro fora do tamanho e malformada. */
    if (parse_answers(resp, len, rrs, DNS_MAX_RR, &nrr) != 0) {
        return DNS_ERR_MALFORMED;
    }

    /* Fase 11: so interessam os registros MX da classe IN. Outros tipos que o
     * servidor coloca nas answers (CNAME, por exemplo) sao ignorados. */
    for (int i = 0; i < nrr && found < max_mx; i++) {
        if (rrs[i].type != DNS_TYPE_MX || rrs[i].rrclass != DNS_CLASS_IN) {
            continue;
        }

        /* Um MX com o RDATA quebrado invalida a resposta inteira. */
        if (parse_mx_rdata(resp, len, &rrs[i], &mx[found]) != 0) {
            return DNS_ERR_MALFORMED;
        }

        /* "Null MX" (RFC 7505): exchange "." diz que o dominio nao recebe
         * e-mail. Equivale a nao ter MX. */
        if (mx[found].exchange[0] == '\0') {
            continue;
        }

        found++;
    }

    *count = found;
    return found > 0 ? DNS_OK : DNS_ERR_NO_MX;
}
