# Trabalho 01 — Cliente DNS (consultas MX)

Fundamentos de Redes de Computadores — Prof. Tiago Alves — FCTE/UnB

## Integrantes

| Nome | Matrícula |
|---|---|
| Luiza Maluf Amorim| 221008294|
| | |
| | |
| | |

## Sistema operacional

TODO

## Ambiente de desenvolvimento

TODO (compilador e versão, editor, ferramentas de teste: dig, Wireshark)

## Como construir

```sh
make
```

## Como testar

```sh
make test
```

O teste da Fase 5 troca uma consulta e uma resposta UDP em `127.0.0.1`,
usando uma porta local escolhida pelo sistema. Ele não depende de um
servidor DNS externo.

## Como executar

```sh
./meu_cliente <dominio> <ip_servidor_dns>
```

## Telas (instruções de uso)

```
$ ./meu_cliente unb.br 8.8.8.8
unb.br <> unb-br.mail.protection.outlook.com

$ ./meu_cliente imagdaskdasdasj.br 1.1.1.1
Dominio imagdaskdasdasj.br nao encontrado

$ ./meu_cliente fga.unb.br 8.8.8.8
Dominio fga.unb.br nao possui entrada MX

$ ./meu_cliente unb.br 1.2.3.4
Nao foi possível coletar entrada MX para unb.br
```

## Limitações conhecidas

TODO
