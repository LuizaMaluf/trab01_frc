#!/bin/sh

# Fase 13: os quatro cenarios do enunciado, contra servidores DNS reais.
# Precisa de internet (UDP porta 53) e leva cerca de 6 segundos por causa do
# cenario 4. As respostas dependem dos dados DNS publicados no momento do teste:
# se a UnB alterar o DNS de unb.br ou fga.unb.br, os cenarios 1 e 3 podem mudar.

set -u

program=${1:-./meu_cliente}
failures=0

fail()
{
    printf 'FALHOU: %s\n' "$1" >&2
    failures=$((failures + 1))
}

# check <descricao> <saida obtida> <codigo de saida> <saida esperada> <codigo esperado>
check()
{
    if [ "$2" = "$4" ] && [ "$3" -eq "$5" ]; then
        printf 'PASSOU: %s\n  %s\n' "$1" "$2"
    else
        fail "$1"
        printf '  obtido:   (codigo %s) %s\n  esperado: (codigo %s) %s\n' "$3" "$2" "$5" "$4" >&2
    fi
}

# Cenario 1: resolucao bem sucedida. O nome do servidor de e-mail pode mudar,
# entao confere o formato "unb.br <> <servidor>" e o codigo de saida 0.
actual=$("$program" unb.br 8.8.8.8); code=$?
case $actual in
    'unb.br <> '?*)
        if [ "$code" -eq 0 ]; then
            printf 'PASSOU: cenario 1: unb.br tem MX\n  %s\n' "$actual"
        else
            fail "cenario 1: codigo de saida $code (esperado 0)"
        fi ;;
    *)
        fail 'cenario 1: unb.br deveria imprimir "unb.br <> servidor"'
        printf '  obtido: %s\n  (sem internet ou sem acesso ao 8.8.8.8:53?)\n' "$actual" >&2 ;;
esac

# Cenario 2: nome de dominio que nao existe (NXDOMAIN).
actual=$("$program" imagdaskdasdasj.br 1.1.1.1); code=$?
check 'cenario 2: dominio inexistente' "$actual" "$code" \
    'Dominio imagdaskdasdasj.br nao encontrado' 1

# Cenario 3: dominio existe, mas nao possui entrada MX.
actual=$("$program" fga.unb.br 8.8.8.8); code=$?
check 'cenario 3: dominio sem MX' "$actual" "$code" \
    'Dominio fga.unb.br nao possui entrada MX' 1

# Cenario 4: servidor que nao existe/nao atende. Tres tentativas de 2 segundos.
start=$(date +%s)
actual=$("$program" unb.br 1.2.3.4); code=$?
elapsed=$(( $(date +%s) - start ))
check 'cenario 4: servidor sem resposta' "$actual" "$code" \
    'Nao foi possível coletar entrada MX para unb.br' 1
if [ "$elapsed" -lt 5 ] || [ "$elapsed" -gt 8 ]; then
    fail "cenario 4: levou ${elapsed}s (esperado cerca de 6s: 3 tentativas de 2s)"
else
    printf '  tempo: %ss (3 tentativas de 2s)\n' "$elapsed"
fi

if [ "$failures" -ne 0 ]; then
    printf '%s verificacao(oes) da Fase 13 falharam.\n' "$failures" >&2
    exit 1
fi

printf 'Todos os testes da Fase 13 passaram.\n'
