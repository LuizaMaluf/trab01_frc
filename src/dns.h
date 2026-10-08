#ifndef DNS_H
#define DNS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define DNS_PORT        53
#define DNS_MAX_MSG     512   /* limite de mensagem DNS sobre UDP (RFC 1035 4.2.1) */
#define DNS_TIMEOUT_SEC 2
#define DNS_MAX_TRIES   3
#define DNS_TYPE_MX     15
#define DNS_CLASS_IN    1
#define DNS_MAX_NAME    256
#define DNS_MAX_WIRE_NAME 255
#define DNS_MAX_MX      16
#define DNS_HEADER_LEN  12    /* tamanho fixo do header (RFC 1035 4.1.1) */
#define DNS_QUESTION_FIXED_LEN 4   /* QTYPE + QCLASS, depois do nome (RFC 1035 4.1.2) */
#define DNS_RR_FIXED_LEN       10  /* TYPE + CLASS + TTL + RDLENGTH, depois do nome (RFC 1035 4.1.3) */
#define DNS_MAX_RR      32    /* registros de resposta guardados por parse_answers */

/* Campos das flags do header: QR (bit 15) e RCODE (bits 0-3). */
#define DNS_FLAG_QR(flags)  (((flags) >> 15) & 0x1)
#define DNS_RCODE(flags)    ((flags) & 0x000F)
#define DNS_RCODE_OK        0     /* sem erro */
#define DNS_RCODE_NXDOMAIN  3     /* nome nao existe */

typedef enum {
    DNS_OK = 0,
    DNS_ERR_NXDOMAIN,     /* RCODE 3: dominio nao existe */
    DNS_ERR_NO_MX,        /* RCODE 0, mas nenhuma resposta TYPE 15 */
    DNS_ERR_NO_RESPONSE,  /* timeout apos DNS_MAX_TRIES tentativas */
    DNS_ERR_MALFORMED     /* resposta invalida / outro RCODE */
} dns_status_t;

typedef struct {
    uint16_t preference;
    char exchange[DNS_MAX_NAME];
} mx_record_t;

/* Header de 12 bytes de uma mensagem DNS, ja convertido de network byte order. */
typedef struct {
    uint16_t id;
    uint16_t flags;     /* QR | OPCODE | AA | TC | RD | RA | Z | RCODE */
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/* Um Resource Record da secao de respostas (Fase 10), sem o nome nem o RDATA.
 * O RDATA nao e copiado: rdata_offset aponta para onde ele comeca na mensagem,
 * porque os nomes dentro dele podem usar ponteiros de compressao e so
 * fazem sentido junto com a mensagem inteira. */
typedef struct {
    uint16_t type;          /* 15 = MX */
    uint16_t rrclass;       /* 1 = IN ("class" e palavra reservada em C++) */
    uint32_t ttl;           /* segundos que a resposta pode ficar em cache */
    uint16_t rdlength;      /* tamanho do RDATA em bytes */
    size_t   rdata_offset;  /* posicao do RDATA dentro da mensagem */
} dns_rr_t;

/* ---------- query.c: montagem da consulta ----------
 * Converte "unb.br" para 03 'u' 'n' 'b' 02 'b' 'r' 00.
 * Retorna o tamanho codificado ou -1 se o dominio for invalido ou nao couber. */
int encode_dns_name(const char *domain, uint8_t *buf, size_t buflen);

/*
 * Monta header (12 bytes) + question (QNAME, QTYPE=MX, QCLASS=IN) em buf.
 * Retorna o tamanho da mensagem ou -1 em erro. */
int build_query(uint8_t *buf, size_t buflen, const char *domain, uint16_t id);

/* ---------- net.c: transporte UDP ----------
 * Envia uma consulta UDP para server_ip:53 e recebe uma resposta.
 * Aguarda ate DNS_TIMEOUT_SEC por tentativa e faz ate DNS_MAX_TRIES envios.
 * Retorna o tamanho da resposta ou -1 em erro/ausencia de resposta. */
int send_and_receive(const char *server_ip, const uint8_t *query, size_t qlen,
                     uint8_t *resp, size_t resplen, uint16_t id);

/* Mesmo transporte com porta configuravel para testes locais. */
int send_and_receive_to(const char *server_ip, uint16_t port,
                        const uint8_t *query, size_t qlen,
                        uint8_t *resp, size_t resplen, uint16_t id);

/* ---------- parse.c: interpretacao da resposta ----------
 * Le os DNS_HEADER_LEN primeiros bytes de msg em *hdr (Fase 7).
 * Nao valida QR nem RCODE; isso e feito por parse_response.
 * Retorna 0 ou -1 se msg for nulo ou msglen < DNS_HEADER_LEN. */
int parse_header(const uint8_t *msg, size_t msglen, dns_header_t *hdr);

/*
 * Le um nome a partir de msg[offset], seguindo ponteiros de compressao (0xC0).
 * Escreve o nome em formato "a.b.c" em out.
 * Retorna quantos bytes o nome ocupa na posicao ORIGINAL (para avancar o cursor),
 * ou -1 em erro. */
int read_name(const uint8_t *msg, size_t msglen, size_t offset,
              char *out, size_t outlen);

/*
 * Pula as qdcount questions que comecam em msg[offset] (cada uma: nome + 4 bytes).
 * Retorna o offset logo depois da ultima question (onde comeca a secao de
 * respostas) ou -1 se alguma estiver truncada ou com nome invalido. */
int skip_questions(const uint8_t *msg, size_t msglen, size_t offset, uint16_t qdcount);

/*
 * Le o Resource Record que comeca em msg[offset] (Fase 10):
 * NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA. Preenche *rr, sem copiar o RDATA.
 * Retorna quantos bytes o registro inteiro ocupa (para avancar o cursor para o
 * proximo) ou -1 se ele nao couber na mensagem. */
int parse_rr(const uint8_t *msg, size_t msglen, size_t offset, dns_rr_t *rr);

/*
 * Percorre a secao de respostas da mensagem (Fase 10): header, questions e
 * ANCOUNT registros. Guarda ate max_rrs registros em rrs[0..*count-1] e valida
 * a estrutura de todos, mesmo os que nao cabem em rrs.
 * Retorna 0 ou -1 se a mensagem estiver truncada ou malformada.
 * Nao olha o RCODE: isso e feito por parse_response. */
int parse_answers(const uint8_t *msg, size_t msglen,
                  dns_rr_t *rrs, int max_rrs, int *count);

/* Interpreta a resposta: verifica RCODE, pula a question, percorre as
 * answers e extrai os registros MX (TYPE 15) em mx[0..*count-1]. */
dns_status_t parse_response(const uint8_t *resp, size_t len,
                            mx_record_t *mx, int max_mx, int *count);

/* ---------- client.c: orquestracao e saida ----------
 * Orquestra a consulta: gera o ID aleatorio, monta a query, envia a server_ip:port,
 * interpreta a resposta e escreve o resultado em out, no formato do enunciado:
 *   MX encontrado   -> "dominio <> servidor" (uma linha por MX)
 *   NXDOMAIN        -> "Dominio X nao encontrado"
 *   sem MX          -> "Dominio X nao possui entrada MX"
 *   sem resposta ou resposta invalida -> "Nao foi possível coletar entrada MX para X"
 *   nome de dominio invalido          -> "Dominio X invalido"
 * A porta e parametro para os testes usarem um servidor local; main usa DNS_PORT.
 * Retorna 0 se imprimiu ao menos um MX e 1 em qualquer outro resultado. */
int run_client(FILE *out, const char *domain, const char *server_ip, uint16_t port);

#endif
