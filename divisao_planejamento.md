# Divisão do planejamento

O desenvolvimento será dividido entre duas pessoas, alternando períodos de trabalho paralelo com etapas de integração. A Pessoa A ficará concentrada principalmente na comunicação de rede, enquanto a Pessoa B desenvolverá o parser das respostas DNS. As etapas iniciais, as integrações e a validação final serão realizadas em conjunto para evitar incompatibilidades entre os componentes.

| Momento | Pessoa A | Pessoa B | Situação |
|---|---|---|---|
| **Base** | **Fase 0–1** — projeto e argumentos | **Fase 0–1** — projeto e testes | ✅ Concluído |
| **Paralelo 1** | **Fase 2** — codificação do domínio ✅ | **Fase 3** — Header DNS ✅ | ✅ Concluído |
| **Integração 1** | **Fase 4** — Query completa | **Fase 4** — Query completa | ✅ Concluído — pacote revisado e incluído em `make test` |
| **Paralelo 2** | **Fase 5** — Socket UDP ✅ | **Fase 7** — Parser do Header usando dados de teste ✅ | ✅ Concluído |
| **Paralelo 3** | **Fase 6** — timeout e retransmissão ✅ | **Fases 8–9** — RCODE ✅ + `read_dns_name()` ✅ | ✅ Concluído |
| **Paralelo 4** | Testar e estabilizar **Fases 5–6** | **Fases 10–11** — Resource Records ✅ + MX ✅ | ✅ Concluído — falta só estabilizar a rede (Pessoa A) |
| **Integração 2** | **Fase 12** — conectar comunicação + parser | **Fase 12** — conectar comunicação + parser | ⬜ Pendente |
| **Validação** | **Fase 13** | **Fase 13** | ⬜ Pendente |
| **Final** | **Fase 14** — revisão do código | **Fase 15** — finalizar documentação | ⬜ Pendente |
| **Entrega** | Revisão cruzada | Revisão cruzada | ⬜ Pendente |

## Independência das fases paralelas

- **Paralelo 1:** a codificação do domínio e a construção do Header DNS produzem partes separadas do pacote, podendo ser implementadas e testadas isoladamente antes da montagem da Query.
- **Paralelo 2:** o socket apenas envia e recebe bytes, enquanto o parser pode ser desenvolvido com respostas DNS salvas para teste, sem depender de uma comunicação real.
- **Paralelo 3:** o timeout pertence à camada de rede, enquanto a análise do RCODE e a leitura de nomes pertencem ao conteúdo da resposta recebida.
- **Paralelo 4:** a estabilização da rede não altera o formato dos dados DNS, permitindo que a leitura dos registros e a extração do MX avancem com pacotes de teste conhecidos.

As fases seguem esta ordem: preparação da base, construção da consulta DNS, desenvolvimento paralelo da rede e do parser, integração dos componentes, validação dos cenários exigidos e revisão final. Cada integração deve ocorrer somente após os testes das fases anteriores.
