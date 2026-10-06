#include <stdio.h>
#include "dns.h"

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <dominio> <ip_servidor_dns>\n", argv[0]);
        return 1;
    }

    const char *domain = argv[1];
    const char *server_ip = argv[2];

    printf("Dominio: %s\n", domain);
    printf("Servidor DNS: %s\n", server_ip);

    /* TODO (Pessoa 4):
     * 1. gerar ID aleatorio de 16 bits
     * 2. build_query
     * 3. send_and_receive  (-1 -> "Nao foi possível coletar entrada MX para X")
     * 4. parse_response
     * 5. imprimir conforme o status:
     *    DNS_OK          -> "dominio <> servidor_mx" (uma linha por MX)
     *    DNS_ERR_NXDOMAIN -> "Dominio X nao encontrado"
     *    DNS_ERR_NO_MX    -> "Dominio X nao possui entrada MX" */
    return 0;
}
