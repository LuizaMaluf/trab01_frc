#!/bin/sh

set -eu

program=${1:-./meu_cliente}

fail()
{
    printf 'FALHOU: %s\n' "$1" >&2
    exit 1
}

# Servidor DNS com IP invalido: a consulta falha antes de usar a rede, e o
# programa so imprime o resultado (sem eco dos argumentos).
if actual=$("$program" unb.br IP-invalido); then
    fail 'IP de servidor invalido terminou com sucesso'
fi
[ "$actual" = 'Nao foi possível coletar entrada MX para unb.br' ] ||
    fail 'mensagem para servidor invalido'

check_invalid()
{
    if actual=$("$program" "$@" 2>&1); then
        fail 'comando invalido terminou com sucesso'
    fi

    expected="Uso: $program <dominio> <ip_servidor_dns>"
    [ "$actual" = "$expected" ] || fail 'mensagem de uso incorreta'
}

check_invalid
check_invalid unb.br
check_invalid unb.br 8.8.8.8 argumento_extra

printf 'Todos os testes das fases 0 e 1 passaram.\n'
