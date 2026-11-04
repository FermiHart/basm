<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Medição de desempenho

O build atual é descrito em [docs/BUILD.md](../../docs/BUILD.md). Para construir
as ferramentas host e conferir os testes de SHA e assinatura:

```sh
make host
build/host/test-sha
build/host/test-sign
python3 tests/campaign/sha_modes_test.py
```

Esses testes verificam resultados; suas durações não são um benchmark.
O build host usa compilador e runtime do host. A lane soberana usa os insumos
Bear, BearLinker e blibc fornecidos explicitamente.

## Harness de comparação retido

`perf_campaign.py` conserva a interface de integração para pares de binários
com recibos de diagnóstico compatíveis. Ele exige `lane` igual a
`HOST_DIAGNOSTIC_NOT_SOVEREIGN`, `status` igual a
`BUILT_FROM_RETAINED_HOST_SNAPSHOT`, o artefato `basm-host` e os campos de
compilador, flags e modo SHA verificados por `load_lane` e
`validate_matching_lanes` no próprio script.

Os recibos `bear-basm-build-v1` produzidos pelo build standalone atual são
outro formato e não podem ser apresentados como esses recibos de integração.
O harness não converte nem inventa a identidade de uma build. Forneça o par
real de executáveis e recibos compatíveis para usar essa interface.

```sh
python3 tests/campaign/perf_campaign.py --help
```

A comparação fixa o workload, valida os outputs, alterna a ordem de execução
dos pares e mantém os casos de cache separados por ferramenta. Ela inclui o
custo de criação do processo e publicação dos resultados quando aplicável.
Casos escolhidos com `--cases` são verificações parciais, não o protocolo
completo. O experimento de configuração SHA permanece identificado
separadamente de uma comparação entre revisões do código.

Uma conclusão de desempenho deve acompanhar as identidades dos binários,
recibos, corpus, host e método realmente usados. Builds com toolchains,
configurações ou workloads diferentes não isolam o efeito de uma mudança de
fonte. Resultados dessa integração não constituem qualificação soberana nem
uma comparação completa com NASM.
