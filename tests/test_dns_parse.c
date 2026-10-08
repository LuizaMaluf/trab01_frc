#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"

/* Fases 7-11: interpretacao da resposta DNS com dados de teste fixos.
 * Nenhum caso abre socket; as respostas sao arrays montados a mao (RFC 1035 4.1). */

static int failures = 0;

/* ---------- Fase 7: header da resposta ---------- */

static void print_header(const dns_header_t *hdr)
{
    printf("  Transaction ID: %u | QR: %u | RCODE: %u | Questions: %u | "
           "Answers: %u | Authority: %u | Additional: %u\n",
           hdr->id, DNS_FLAG_QR(hdr->flags), DNS_RCODE(hdr->flags),
           hdr->qdcount, hdr->ancount, hdr->nscount, hdr->arcount);
}

static void check_header(const char *description, const uint8_t *msg, size_t len,
                         uint16_t id, uint16_t flags, uint16_t qd, uint16_t an,
                         uint16_t ns, uint16_t ar)
{
    dns_header_t hdr;

    memset(&hdr, 0xFF, sizeof(hdr));

    if (parse_header(msg, len, &hdr) != 0) {
        fprintf(stderr, "FALHOU: %s (parse_header retornou erro)\n", description);
        failures++;
        return;
    }

    if (hdr.id != id || hdr.flags != flags || hdr.qdcount != qd ||
        hdr.ancount != an || hdr.nscount != ns || hdr.arcount != ar) {
        fprintf(stderr, "FALHOU: %s\n"
                        "  obtido:   id=%04x flags=%04x qd=%u an=%u ns=%u ar=%u\n"
                        "  esperado: id=%04x flags=%04x qd=%u an=%u ns=%u ar=%u\n",
                description,
                hdr.id, hdr.flags, hdr.qdcount, hdr.ancount, hdr.nscount, hdr.arcount,
                id, flags, qd, an, ns, ar);
        failures++;
        return;
    }

    printf("PASSOU: %s\n", description);
    print_header(&hdr);
}

static void check_header_rejected(const char *description, const uint8_t *msg,
                                  size_t len)
{
    dns_header_t hdr;

    if (parse_header(msg, len, &hdr) != -1) {
        fprintf(stderr, "FALHOU: %s deveria ser rejeitado\n", description);
        failures++;
        return;
    }

    printf("PASSOU: rejeicao de %s\n", description);
}

static void test_fase7_header(void)
{
    /* Resposta tipica de um resolvedor recursivo: QR=1, RD=1, RA=1, RCODE=0
     * (flags 0x8180); 1 pergunta, 1 resposta, 0 autoridade, 1 adicional.
     * A question vem junto para a mensagem ter mais de 12 bytes. */
    static const uint8_t resposta_ok[] = {
        0xab, 0x74,             /* ID 43892 */
        0x81, 0x80,             /* flags */
        0x00, 0x01,             /* QDCOUNT */
        0x00, 0x01,             /* ANCOUNT */
        0x00, 0x00,             /* NSCOUNT */
        0x00, 0x01,             /* ARCOUNT */
        3, 'u', 'n', 'b', 2, 'b', 'r', 0, 0x00, 0x0f, 0x00, 0x01
    };

    /* NXDOMAIN: flags 0x8183 (RCODE 3); 1 pergunta, 0 respostas, 1 autoridade. */
    static const uint8_t resposta_nxdomain[] = {
        0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
    };

    /* Contagens com os dois bytes significativos, para conferir a ordem
     * (network byte order): QD=0x0100=256, AN=0x0102=258, NS=0x00ff=255, AR=0x1000=4096. */
    static const uint8_t resposta_contagens[] = {
        0xff, 0xff, 0x80, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0xff, 0x10, 0x00
    };

    uint8_t query[DNS_MAX_MSG];
    int qlen;

    check_header("header de resposta com 1 answer",
                 resposta_ok, sizeof(resposta_ok), 0xab74, 0x8180, 1, 1, 0, 1);
    check_header("header NXDOMAIN",
                 resposta_nxdomain, sizeof(resposta_nxdomain), 0x1234, 0x8183, 1, 0, 1, 0);
    check_header("header com contagens multi-byte",
                 resposta_contagens, sizeof(resposta_contagens),
                 0xffff, 0x8000, 256, 258, 255, 4096);

    check_header_rejected("mensagem com 11 bytes", resposta_ok, 11);
    check_header_rejected("mensagem vazia", resposta_ok, 0);
    check_header_rejected("mensagem nula", NULL, DNS_HEADER_LEN);

    /* Ida e volta com build_query: o Transaction ID e os campos fixados pelo
     * enunciado devem ser lidos de volta exatamente como foram gravados. */
    qlen = build_query(query, sizeof(query), "unb.br", 0x1234);
    if (qlen < 0) {
        fprintf(stderr, "FALHOU: build_query nao montou a consulta de referencia\n");
        failures++;
    } else {
        check_header("header da consulta montada por build_query",
                     query, (size_t)qlen, 0x1234, 0x0100, 1, 0, 0, 0);
    }
}

/* ---------- Fase 8: bit QR e codigo de resposta (RCODE) ---------- */

static void check_status(const char *description, const uint8_t *resp, size_t len,
                         dns_status_t expected)
{
    mx_record_t mx[DNS_MAX_MX];
    int count = -1;
    dns_status_t status = parse_response(resp, len, mx, DNS_MAX_MX, &count);

    if (status != expected || count != 0) {
        fprintf(stderr, "FALHOU: %s (status %d, count %d; esperado status %d, count 0)\n",
                description, (int)status, count, (int)expected);
        failures++;
        return;
    }

    printf("PASSOU: %s\n", description);
}

/* Question "foo.br" tipo MX classe IN, usada em todas as respostas abaixo. */
#define QUESTION_FOO_BR 3, 'f', 'o', 'o', 2, 'b', 'r', 0, 0x00, 0x0f, 0x00, 0x01

static void test_fase8_rcode(void)
{
    /* NXDOMAIN (RCODE 3) com um registro SOA na secao de autoridade, como um
     * resolvedor real devolve. A autoridade nao e lida pelo parser. */
    static const uint8_t nxdomain_soa[] = {
        0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        QUESTION_FOO_BR,
        0xc0, 0x0c,             /* NAME -> ponteiro para "foo.br" */
        0x00, 0x06,             /* TYPE SOA */
        0x00, 0x01,             /* CLASS IN */
        0x00, 0x00, 0x0e, 0x10, /* TTL 3600 */
        0x00, 0x1b,             /* RDLENGTH 27 */
        2, 'n', 's', 0xc0, 0x0c,            /* MNAME ns.foo.br */
        0xc0, 0x0c,                         /* RNAME */
        0x00, 0x00, 0x00, 0x01,             /* SERIAL */
        0x00, 0x00, 0x0e, 0x10,             /* REFRESH */
        0x00, 0x00, 0x03, 0x84,             /* RETRY */
        0x00, 0x09, 0x3a, 0x80,             /* EXPIRE */
        0x00, 0x00, 0x00, 0x3c              /* MINIMUM */
    };

    /* NOERROR (RCODE 0) sem nenhuma resposta: dominio existe, sem MX. */
    static const uint8_t nodata[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR
    };

    /* SERVFAIL (RCODE 2) e REFUSED (RCODE 5): falha de coleta. */
    static const uint8_t servfail[] = {
        0x12, 0x34, 0x81, 0x82, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR
    };
    static const uint8_t refused[] = {
        0x12, 0x34, 0x81, 0x85, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR
    };

    /* QR = 0: e uma consulta, nao uma resposta. */
    static const uint8_t qr_zero[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR
    };

    check_status("NXDOMAIN com SOA na autoridade",
                 nxdomain_soa, sizeof(nxdomain_soa), DNS_ERR_NXDOMAIN);
    check_status("NXDOMAIN truncado no meio da autoridade",
                 nxdomain_soa, 12 + 12 + 6, DNS_ERR_NXDOMAIN);
    check_status("NXDOMAIN so com o header",
                 nxdomain_soa, DNS_HEADER_LEN, DNS_ERR_NXDOMAIN);
    check_status("NOERROR sem respostas (sem MX)",
                 nodata, sizeof(nodata), DNS_ERR_NO_MX);
    check_status("SERVFAIL (RCODE 2) e falha de coleta",
                 servfail, sizeof(servfail), DNS_ERR_MALFORMED);
    check_status("REFUSED (RCODE 5) e falha de coleta",
                 refused, sizeof(refused), DNS_ERR_MALFORMED);
    check_status("QR = 0 (consulta ecoada) e malformada",
                 qr_zero, sizeof(qr_zero), DNS_ERR_MALFORMED);
    check_status("mensagem com 11 bytes e malformada",
                 nodata, 11, DNS_ERR_MALFORMED);
    check_status("mensagem vazia e malformada",
                 nodata, 0, DNS_ERR_MALFORMED);
}

/* ---------- Fase 9: leitura de nomes, com compressao ---------- */

static void check_name(const char *description, const uint8_t *msg, size_t msglen,
                       size_t offset, const char *expected, int expected_consumed)
{
    char out[DNS_MAX_NAME];
    int consumed;

    memset(out, 0x7F, sizeof(out));
    consumed = read_name(msg, msglen, offset, out, sizeof(out));

    if (consumed != expected_consumed || strcmp(out, expected) != 0) {
        fprintf(stderr, "FALHOU: %s\n  obtido:   \"%s\" (consumiu %d)\n"
                        "  esperado: \"%s\" (consumiu %d)\n",
                description, consumed < 0 ? "(erro)" : out, consumed,
                expected, expected_consumed);
        failures++;
        return;
    }

    printf("PASSOU: %s -> \"%s\" (%d bytes na posicao original)\n",
           description, out, consumed);
}

static void check_name_rejected(const char *description, const uint8_t *msg,
                                size_t msglen, size_t offset, size_t outlen)
{
    /* Sentinela depois de outlen: read_name nunca pode escrever la. */
    char out[DNS_MAX_NAME + 4];

    memset(out, 0x7F, sizeof(out));

    if (read_name(msg, msglen, offset, out, outlen) != -1) {
        fprintf(stderr, "FALHOU: %s deveria ser rejeitado\n", description);
        failures++;
        return;
    }

    for (size_t i = outlen; i < outlen + 4 && i < sizeof(out); i++) {
        if (out[i] != 0x7F) {
            fprintf(stderr, "FALHOU: %s escreveu alem de outlen\n", description);
            failures++;
            return;
        }
    }

    printf("PASSOU: rejeicao de %s\n", description);
}

static void test_fase9_read_name(void)
{
    /* Mensagem com header, "unb.br" em 12, e nomes comprimidos depois:
     *   20: 04 'm' 'a' 'i' 'l' C0 0C          -> mail.unb.br   (7 bytes)
     *   27: 02 'f' 'g' C0 0C                  -> fg.unb.br     (5 bytes)
     *   32: 03 'w' 'w' 'w' C0 1B              -> www.fg.unb.br (6 bytes, 2 saltos)
     *   38: C0 0C                             -> unb.br        (2 bytes)
     *   40: 00                                -> raiz          (1 byte) */
    static const uint8_t msg[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3, 'u', 'n', 'b', 2, 'b', 'r', 0,
        4, 'm', 'a', 'i', 'l', 0xc0, 0x0c,
        2, 'f', 'g', 0xc0, 0x0c,
        3, 'w', 'w', 'w', 0xc0, 0x1b,
        0xc0, 0x0c,
        0x00
    };

    static const uint8_t simples[] = { 3, 'u', 'n', 'b', 2, 'b', 'r', 0 };

    /* Casos invalidos */
    static const uint8_t rotulo_64[] = { 0x40, 'a', 0 };
    static const uint8_t reservado[] = { 0x80, 'a', 0 };
    static const uint8_t ponteiro_frente[] = { 0xc0, 0x04, 0, 0, 3, 'u', 'n', 'b', 0 };
    static const uint8_t ponteiro_self[] = { 0xc0, 0x00, 0 };
    static const uint8_t ponteiro_fora[] = { 3, 'u', 'n', 'b', 0, 0xff, 0xff };
    static const uint8_t ponteiro_truncado[] = { 3, 'u', 'n', 'b', 0, 0xc0 };
    static const uint8_t sem_terminador[] = { 3, 'u', 'n', 'b', 2, 'b', 'r' };
    static const uint8_t rotulo_curto[] = { 3, 'u', 'n' };

    /* 5 rotulos de 63 'a': 319 caracteres reconstruidos, acima de 255. */
    uint8_t longo[5 * 64 + 1];
    for (int i = 0; i < 5; i++) {
        longo[i * 64] = 63;
        memset(longo + i * 64 + 1, 'a', 63);
    }
    longo[5 * 64] = 0;

    check_name("nome simples em offset 0", simples, sizeof(simples), 0, "unb.br", 8);
    check_name("nome simples dentro da mensagem", msg, sizeof(msg), 12, "unb.br", 8);
    check_name("ponteiro puro (C0 0C)", msg, sizeof(msg), 38, "unb.br", 2);
    check_name("rotulo seguido de ponteiro", msg, sizeof(msg), 20, "mail.unb.br", 7);
    check_name("dois saltos encadeados", msg, sizeof(msg), 32, "www.fg.unb.br", 6);
    check_name("nome raiz (00)", msg, sizeof(msg), 40, "", 1);
    check_name("mensagem terminando exatamente no fim do nome", msg, 20, 12, "unb.br", 8);

    check_name_rejected("rotulo com tamanho 64", rotulo_64, sizeof(rotulo_64), 0, DNS_MAX_NAME);
    check_name_rejected("byte de tamanho reservado (10xxxxxx)", reservado, sizeof(reservado), 0, DNS_MAX_NAME);
    check_name_rejected("ponteiro para frente", ponteiro_frente, sizeof(ponteiro_frente), 0, DNS_MAX_NAME);
    check_name_rejected("ponteiro para si mesmo", ponteiro_self, sizeof(ponteiro_self), 0, DNS_MAX_NAME);
    check_name_rejected("ponteiro para fora da mensagem", ponteiro_fora, sizeof(ponteiro_fora), 5, DNS_MAX_NAME);
    check_name_rejected("ponteiro truncado (so 1 byte)", ponteiro_truncado, sizeof(ponteiro_truncado), 5, DNS_MAX_NAME);
    check_name_rejected("nome sem terminador", sem_terminador, sizeof(sem_terminador), 0, DNS_MAX_NAME);
    check_name_rejected("rotulo maior que a mensagem", rotulo_curto, sizeof(rotulo_curto), 0, DNS_MAX_NAME);
    check_name_rejected("offset igual a msglen", simples, sizeof(simples), sizeof(simples), DNS_MAX_NAME);
    check_name_rejected("nome reconstruido com mais de 255 caracteres", longo, sizeof(longo), 0, DNS_MAX_NAME);
    check_name_rejected("buffer de saida menor que o nome", simples, sizeof(simples), 0, 6);
}

int main(void)
{
    test_fase7_header();
    test_fase8_rcode();
    test_fase9_read_name();

    if (failures != 0) {
        fprintf(stderr, "%d teste(s) do parser falharam.\n", failures);
        return 1;
    }

    printf("Todos os testes das Fases 7-9 passaram.\n");
    return 0;
}
