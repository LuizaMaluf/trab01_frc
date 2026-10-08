#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dns.h"

/* Fase 12: run_client de ponta a ponta contra um servidor DNS falso em
 * 127.0.0.1. O servidor devolve a propria consulta recebida, com as flags e a
 * secao de respostas trocadas pelo cenario. Nao depende de internet. */

typedef enum {
    SERVER_REPLY,   /* responde a primeira consulta */
    SERVER_SILENT,  /* recebe mas nunca responde (timeout) */
    SERVER_NONE     /* nao ha servidor: o cliente falha antes da rede */
} server_mode_t;

typedef struct {
    const char *description;
    const char *domain;
    const char *server_ip;          /* NULL: usa o servidor local de teste */
    server_mode_t mode;
    uint16_t flags;                 /* flags da resposta (RCODE nos 4 bits finais) */
    uint16_t ancount;
    const uint8_t *tail;            /* registros anexados depois da question */
    size_t tail_len;
    size_t truncate_to;             /* 0: resposta inteira; senao, so N bytes */
    const char *expected_output;
    int expected_rc;
} scenario_t;

static int failures = 0;

/* O servidor falso informa, por este pipe, o Transaction ID de cada consulta
 * que recebeu. Assim o teste confere que o cliente sorteia um ID por consulta. */
static int id_pipe[2];
static uint16_t seen_ids[32];
static size_t seen_count = 0;

/* Registros de resposta. Todos usam C0 0C: o NAME e o da question. */
static const uint8_t tail_mx_unb[] = {      /* MX 0 unb-br.mail.protection.outlook.com */
    0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x08, 0xbd, 0x00, 0x26,
    0x00, 0x00,
    6, 'u', 'n', 'b', '-', 'b', 'r', 4, 'm', 'a', 'i', 'l',
    10, 'p', 'r', 'o', 't', 'e', 'c', 't', 'i', 'o', 'n',
    7, 'o', 'u', 't', 'l', 'o', 'o', 'k', 3, 'c', 'o', 'm', 0
};

static const uint8_t tail_dois_mx[] = {     /* MX 10 mx1.<dominio> e MX 20 mx2.<dominio> */
    0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x08,
    0x00, 0x0a, 3, 'm', 'x', '1', 0xc0, 0x0c,
    0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x08,
    0x00, 0x14, 3, 'm', 'x', '2', 0xc0, 0x0c
};

static const uint8_t tail_cname_fga[] = {   /* fga.unb.br CNAME fcte.unb.br (sem MX) */
    0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x03, 0x6d, 0x00, 0x07,
    4, 'f', 'c', 't', 'e', 0xc0, 0x10
};

static const uint8_t tail_null_mx[] = {     /* MX 0 "." (RFC 7505) */
    0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x03,
    0x00, 0x00, 0x00
};

#define TAIL(t) (t), sizeof(t)
#define SEM_REGISTROS NULL, 0

/* Servidor falso: confere a consulta recebida e responde. Retorna 0 se tudo
 * certo, ou um codigo de erro para o processo pai conferir. */
static int serve_one(int server, const scenario_t *sc)
{
    struct sockaddr_in client = {0};
    socklen_t client_len = sizeof(client);
    uint8_t received[DNS_MAX_MSG];
    uint8_t expected[DNS_MAX_MSG];
    uint8_t response[DNS_MAX_MSG];
    ssize_t n;
    int expected_len;
    size_t len;
    uint16_t id;

    n = recvfrom(server, received, sizeof(received), 0,
                 (struct sockaddr *)&client, &client_len);
    if (n < DNS_HEADER_LEN) {
        return 2;                       /* o cliente nao enviou a consulta */
    }

    /* A consulta enviada tem que ser exatamente a que build_query monta para o
     * ID que o cliente escolheu: header, QNAME, QTYPE = MX e QCLASS = IN. */
    id = (uint16_t)(((uint16_t)received[0] << 8) | received[1]);
    expected_len = build_query(expected, sizeof(expected), sc->domain, id);
    if (expected_len != n || memcmp(expected, received, (size_t)n) != 0) {
        return 3;
    }

    if (write(id_pipe[1], &id, sizeof(id)) != (ssize_t)sizeof(id)) {
        return 5;
    }

    memcpy(response, received, (size_t)n);
    response[2] = (uint8_t)(sc->flags >> 8);
    response[3] = (uint8_t)sc->flags;
    response[6] = (uint8_t)(sc->ancount >> 8);
    response[7] = (uint8_t)sc->ancount;
    if (sc->tail_len > 0) {
        memcpy(response + n, sc->tail, sc->tail_len);
    }
    len = (size_t)n + sc->tail_len;
    if (sc->truncate_to != 0) {
        len = sc->truncate_to;
    }

    if (sendto(server, response, len, 0,
               (const struct sockaddr *)&client, client_len) != (ssize_t)len) {
        return 4;
    }
    return 0;
}

static void run_scenario(const scenario_t *sc)
{
    struct sockaddr_in local = {0};
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    socklen_t local_len = sizeof(local);
    char text[1024] = "";
    const char *ip = sc->server_ip != NULL ? sc->server_ip : "127.0.0.1";
    uint16_t port = 9;
    FILE *out;
    size_t got;
    pid_t child = -1;
    int server = -1;
    int status = 0;
    int rc;
    int ok = 1;

    if (sc->mode != SERVER_NONE) {
        server = socket(AF_INET, SOCK_DGRAM, 0);
        local.sin_family = AF_INET;
        if (server < 0 ||
            inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) != 1 ||
            bind(server, (const struct sockaddr *)&local, sizeof(local)) < 0 ||
            getsockname(server, (struct sockaddr *)&local, &local_len) < 0 ||
            setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            perror("servidor UDP de teste");
            failures++;
            return;
        }
        port = ntohs(local.sin_port);
    }

    if (sc->mode == SERVER_REPLY) {
        child = fork();
        if (child < 0) {
            perror("fork do teste");
            failures++;
            close(server);
            return;
        }
        if (child == 0) {
            _exit(serve_one(server, sc));
        }
    }

    out = tmpfile();
    if (out == NULL) {
        perror("tmpfile");
        failures++;
        return;
    }

    rc = run_client(out, sc->domain, ip, port);

    fflush(out);
    rewind(out);
    got = fread(text, 1, sizeof(text) - 1, out);
    text[got] = '\0';
    fclose(out);

    if (child > 0) {
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
            fprintf(stderr, "  servidor falso terminou com erro (status %d): a consulta "
                            "enviada pelo cliente nao era a esperada\n",
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            ok = 0;
        }
    }
    if (server >= 0) {
        close(server);
    }
    if (ok && child > 0) {
        uint16_t id;

        if (read(id_pipe[0], &id, sizeof(id)) == (ssize_t)sizeof(id) &&
            seen_count < sizeof(seen_ids) / sizeof(seen_ids[0])) {
            seen_ids[seen_count++] = id;
        }
    }

    if (strcmp(text, sc->expected_output) != 0 || rc != sc->expected_rc) {
        fprintf(stderr, "  obtido:   rc=%d \"%s\"\n  esperado: rc=%d \"%s\"\n",
                rc, text, sc->expected_rc, sc->expected_output);
        ok = 0;
    }

    if (!ok) {
        fprintf(stderr, "FALHOU: %s\n", sc->description);
        failures++;
        return;
    }

    printf("PASSOU: %s\n", sc->description);
    printf("  %s", text);
}

int main(void)
{
    static const scenario_t scenarios[] = {
        { "cenario 1: MX encontrado imprime 'dominio <> servidor'",
          "unb.br", NULL, SERVER_REPLY, 0x8180, 1, TAIL(tail_mx_unb), 0,
          "unb.br <> unb-br.mail.protection.outlook.com\n", 0 },
        { "varios MX: uma linha por MX, na ordem recebida (exchange com ponteiro)",
          "unb.br", NULL, SERVER_REPLY, 0x8180, 2, TAIL(tail_dois_mx), 0,
          "unb.br <> mx1.unb.br\nunb.br <> mx2.unb.br\n", 0 },
        { "cenario 2: NXDOMAIN (RCODE 3) -> 'nao encontrado'",
          "imagdaskdasdasj.br", NULL, SERVER_REPLY, 0x8183, 0, SEM_REGISTROS, 0,
          "Dominio imagdaskdasdasj.br nao encontrado\n", 1 },
        { "cenario 3: dominio existe so com CNAME -> 'nao possui entrada MX'",
          "fga.unb.br", NULL, SERVER_REPLY, 0x8180, 1, TAIL(tail_cname_fga), 0,
          "Dominio fga.unb.br nao possui entrada MX\n", 1 },
        { "dominio existe sem nenhuma resposta (NOERROR vazio) -> 'nao possui entrada MX'",
          "fga.unb.br", NULL, SERVER_REPLY, 0x8180, 0, SEM_REGISTROS, 0,
          "Dominio fga.unb.br nao possui entrada MX\n", 1 },
        { "null MX (exchange \".\") -> 'nao possui entrada MX'",
          "example.com", NULL, SERVER_REPLY, 0x8180, 1, TAIL(tail_null_mx), 0,
          "Dominio example.com nao possui entrada MX\n", 1 },
        { "SERVFAIL (RCODE 2) -> 'nao foi possivel coletar'",
          "unb.br", NULL, SERVER_REPLY, 0x8182, 0, SEM_REGISTROS, 0,
          "Nao foi possível coletar entrada MX para unb.br\n", 1 },
        { "REFUSED (RCODE 5) -> 'nao foi possivel coletar'",
          "unb.br", NULL, SERVER_REPLY, 0x8185, 0, SEM_REGISTROS, 0,
          "Nao foi possível coletar entrada MX para unb.br\n", 1 },
        { "resposta truncada (5 bytes) -> 'nao foi possivel coletar'",
          "unb.br", NULL, SERVER_REPLY, 0x8180, 1, TAIL(tail_mx_unb), 5,
          "Nao foi possível coletar entrada MX para unb.br\n", 1 },
        { "resposta com QR = 0 (consulta ecoada) -> 'nao foi possivel coletar'",
          "unb.br", NULL, SERVER_REPLY, 0x0100, 0, SEM_REGISTROS, 0,
          "Nao foi possível coletar entrada MX para unb.br\n", 1 },
        { "IP de servidor invalido -> 'nao foi possivel coletar' sem tocar na rede",
          "unb.br", "IP-invalido", SERVER_NONE, 0, 0, SEM_REGISTROS, 0,
          "Nao foi possível coletar entrada MX para unb.br\n", 1 },
        { "nome de dominio invalido (rotulo vazio) -> 'invalido'",
          "unb..br", "127.0.0.1", SERVER_NONE, 0, 0, SEM_REGISTROS, 0,
          "Dominio unb..br invalido\n", 1 },
        { "cenario 4: servidor mudo, 3 tentativas de 2s -> 'nao foi possivel coletar'",
          "unb.br", NULL, SERVER_SILENT, 0, 0, SEM_REGISTROS, 0,
          "Nao foi possível coletar entrada MX para unb.br\n", 1 },
    };

    if (pipe(id_pipe) != 0) {
        perror("pipe");
        return 1;
    }

    fflush(stdout);
    for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
        run_scenario(&scenarios[i]);
        fflush(stdout);
    }

    /* Cada consulta sorteia um ID de 16 bits: nao podem ser todos iguais. */
    {
        int distinct = 0;

        for (size_t i = 0; i < seen_count; i++) {
            if (seen_ids[i] != seen_ids[0]) {
                distinct = 1;
            }
        }
        if (seen_count < 2 || !distinct) {
            fprintf(stderr, "FALHOU: Transaction ID nao e aleatorio "
                            "(%zu consultas vistas, todas com o mesmo ID)\n", seen_count);
            failures++;
        } else {
            printf("PASSOU: Transaction ID varia entre consultas (%zu IDs observados)\n",
                   seen_count);
        }
    }

    if (failures != 0) {
        fprintf(stderr, "%d cenario(s) do cliente falharam.\n", failures);
        return 1;
    }

    printf("Todos os testes da Fase 12 passaram.\n");
    return 0;
}
