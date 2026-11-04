<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Verificar contratos e admissão

Execute a partir da raiz do repositório, em Linux x86-64, com Python 3,
compilador C, GNU assembler, linker e objdump disponíveis:

```sh
make host
BASM_CANDIDATE="$PWD/build/host/basm" python3 tests/campaign/test_contracts.py
python3 tests/campaign/test_main.py --basm build/host/basm
python3 tests/campaign/test_generation_version.py --basm build/host/basm-compat
```

A suite de versão usa `basm-compat` para produzir fixtures legadas v2, além de
v3/v4; o executável público mantém seu default v3 para `--emit-attestation`.

Estas são suites de diagnóstico host. A execução não qualifica boot Beyond,
a toolchain soberana, outras plataformas ou todos os encodings x86-64.
Registre o commit, os hashes dos executáveis e o resultado da execução usada
na sua própria avaliação.

## O que as suites verificam

| Suite | Escopo |
| --- | --- |
| `test_contracts.py` | Parser ELF independente, decoder, aliases de registradores, stack, branches, limites de recursos, contratos, targets, identidades de fontes e recibos, comparação com GAS e consumidor C do exemplo revisado |
| `test_main.py` | Publicação de gerações, admissões e recusas, preservação da geração anterior, contrato exigido pelo consumidor e mudanças de identidade |
| `test_generation_version.py` | Aceitação de v4 pelo publicador e recusa de proofs v2/v3 que não atendem à política desse wrapper |

O teste funcional executa somente a função `max_u64` revisada, depois das
verificações de bytes e paridade previstas na suite. Mutações, casos de erro e
o exemplo CPUID são entradas de análise, sem execução automática.

## Interpretar o resultado

`VERIFIED_WITHIN_MODEL` refere-se às obrigações de ABI descritas em
[MODEL.md](MODEL.md), sob suas precondições. A propriedade funcional do recibo
continua `NOT_CHECKED`; observações de um consumidor C não são uma prova
funcional universal.

O recibo do checker não é assinado pela proof v4. O consumidor seleciona o
checker, o contrato, o target e a chave confiável, quando exigida, e repete a
verificação sobre os bytes recebidos. A assinatura do objeto não demonstra
segurança geral de memória, correspondência semântica entre fonte e objeto,
frescor da geração ou confinamento de execução.

Veja [README.md](README.md) para reproduzir a análise e
[PUBLISHER.md](PUBLISHER.md) para a política de publicação e seus limites.
