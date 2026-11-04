<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Verificação independente de contratos

Este diretório entrega uma fatia funcional de verificação de ABI, requisitos e
admissão de artefatos. O assembler continua separado do checker Python. O checker
usa apenas a biblioteca padrão, lê ELF64 e decodifica os bytes da função; não
importa o encoder, o schema de ISA do assembler nem seu trace de `--explain`.

O resultado `VERIFIED_WITHIN_MODEL` significa que as obrigações listadas foram
estabelecidas no modelo fechado, sob as precondições do recibo. Não significa
correção funcional, segurança de memória geral, constant-time, identidade de
signatário, confinamento de execução ou validação da imagem depois do link.

## Executar o exemplo

A lane abaixo é de diagnóstico host: GCC, o runtime host e o provedor Ed25519
empacotado. Ela não substitui a reconstrução soberana com a closure externa.

```sh
make host
mkdir -p build/contract-demo
build/host/basm --target-profile public -f elf64 \
  -o build/contract-demo/max.o contracts/examples/max_u64.basm
python3 tools/contract_check.py \
  --object build/contract-demo/max.o \
  --contract contracts/max_u64.json \
  --source contracts/examples/max_u64.basm \
  > build/contract-demo/result.json
```

Uma verificação posterior pode exigir as mesmas identidades e refazer a análise:

```sh
python3 tools/contract_check.py \
  --object build/contract-demo/max.o \
  --contract contracts/max_u64.json \
  --source contracts/examples/max_u64.basm \
  --expect build/contract-demo/result.json
```

`--expect` confere hashes do objeto inteiro, contrato, target, fonte, checker e
inventário de instruções, além da identidade e extensão da função. Depois disso,
decodifica os bytes e executa novamente a análise. Um JSON com rótulo de aprovação
fabricado não dispensa esse trabalho. Alterar bytes por outros que também
respeitam a ABI invalida o recibo anterior.

O contrato de exemplo contém um mapa de linhas. Por isso `--source` deve ser
fornecido explicitamente e deve corresponder ao hash declarado. O checker nunca
abre um caminho recebido dentro do contrato. O mapa é uma pista diagnóstica
declarada: conferir seu hash e os offsets de instrução não prova que a fonte
produziu os bytes. A análise de ABI depende dos bytes e não desse mapa.

## Contrato e modelo

`max_u64.json` declara:

- a função global ELF `bb_max_u64`, com tamanho não zero;
- a ABI SysV AMD64 e o domínio `hosted-user`;
- requisito `base`, sem suposição adicional de OS;
- clobbers permitidos `rax` e `rflags`;
- no máximo oito bytes de stack privada abaixo do RSP de entrada.

A função usa `RBX` temporariamente e o restaura. Um branch escolhe o máximo
unsigned entre RDI e RSI. O checker estabelece preservação de registradores,
balanço de stack, DF no retorno e limite dos clobbers declarados. O resultado
numérico é conferido por um consumidor C separado; a propriedade funcional no
recibo permanece `NOT_CHECKED`.

O contrato não pode dispensar `RBX`, `RBP`, `R12`–`R15`, mudar a ABI para uma
privada, aceitar instruções desconhecidas ou aumentar os tetos do checker.
Clobbers só podem nomear registradores caller-saved e flags. Aumentar uma
permissão válida no contrato também altera sua identidade e exige nova revisão
pelo consumidor.

Veja [MODEL.md](MODEL.md) para a semântica e as fronteiras exatas.

## Requisitos de CPU e OS

`target-base.json` é uma declaração de ambiente equivalente ao default sem
`--target`. `target-cpuid.json` declara adicionalmente CPUID disponível em
userspace. O exemplo `cpuid_leaf.basm` salva RBX, executa CPUID e o restaura.

```sh
build/host/basm --target-profile public -f elf64 \
  -o build/contract-demo/cpuid.o contracts/examples/cpuid_leaf.basm
python3 tools/contract_check.py \
  --object build/contract-demo/cpuid.o \
  --contract contracts/cpuid_leaf.json \
  --target contracts/target-cpuid.json \
  --source contracts/examples/cpuid_leaf.basm
```

O checker rederiva a necessidade de CPUID a partir dos bytes e exige
`cpuid_user_enabled: true`. A configuração real da máquina não é consultada.
Estabelecer essa declaração é obrigação do consumidor. Target sem os requisitos
retorna `UNPROVEN` e exit code 1; declarar outra CPU não amplia o decoder.
Os testes não executam o exemplo CPUID. XGETBV, SIMD, interrupções, bootstrap,
kernel e trocas de contexto ficam fora deste modelo.

## Diagnósticos e comparação

Uma falha conhecida, como RBX não restaurado, resulta em `REJECTED` com código
`CALLEE_SAVED`, offset de função, offset de arquivo, caminho de instruções e a
pista de linha disponível. Instrução, controle ou recurso não modelado resulta
em `UNPROVEN`. Ambos bloqueiam admissão e retornam exit code 1.

```sh
python3 tools/contract_check.py --describe
python3 tools/contract_check.py --compare-contracts contracts/max_u64.json novo-contrato.json
```

`--describe` exporta o inventário fechado e os tetos. A comparação retorna
`bearbasm-contract-diff-v1`, enumera alterações de função, clobbers, orçamento,
requisitos e fonte, e marca `authorizes_publication: false`. Seu exit code 0
indica somente que a comparação de declarações foi produzida. Ele não substitui
uma execução do checker sobre o objeto.

## Publicação condicionada ao contrato

O publicador externo pode exigir este checker antes de trocar `current.json`:

```sh
python3 tools/publish_generation.py publish \
  --basm build/host/basm --root build/contract-demo/store \
  --source contracts/examples/max_u64.basm --contract contracts/max_u64.json
python3 tools/publish_generation.py verify \
  --basm build/host/basm --root build/contract-demo/store \
  --source contracts/examples/max_u64.basm --contract contracts/max_u64.json
```

`--contract-target FILE` passa uma declaração de target ao checker. Reutilize os
mesmos bytes de contrato e target na verificação: as identidades são exatas, não
normalizações que apagam mudanças. Uma geração com contrato contém
`object.o`, `object.basmproof` e `contract-result.json`; os três hashes constam no
manifesto. Falha do checker ocorre antes da publicação do ponteiro e deixa a
geração anterior selecionada. Verificação de uma geração com recibo exige o
contrato explicitamente fornecido pelo consumidor e reexecuta o checker com
`--expect`.

**A assinatura da proof v4 não assina o recibo do checker nem o manifesto da
geração.** São camadas distintas. O recibo não se transforma em autoridade por
estar no diretório ou por dizer `VERIFIED_WITHIN_MODEL`. O consumidor escolhe
externamente o checker, contrato, target e, quando requerida, a chave confiável
de proveniência, e rederiva o resultado. `--sign SEED_FILE --trusted-key PUB_FILE`
no publicador adiciona a verificação de signatário da proof, sem mudar essa
fronteira. Ambos os argumentos são caminhos de arquivos; `PUB_FILE` contém uma
chave pública obtida pelo consumidor por um canal confiável externo ao artefato.

Veja [PUBLISHER.md](PUBLISHER.md) para os formatos, a política do consumidor,
os comandos de assinatura e os limites de atomicidade da geração. O publicador
não oferece prevenção de rollback para uma geração antiga ainda válida.

Não há promoção de binário de kernel nem execução automática do objeto. A prova
local tem como precondição que a ligação preserve os bytes sem relocations da
função; verificar a imagem final continua sendo trabalho posterior.

## Validação desta fatia

```sh
BASM_CANDIDATE="$PWD/build/host/basm" python3 tests/campaign/test_contracts.py
python3 tests/campaign/test_main.py --basm build/host/basm
```

A primeira suíte cobre o parser independente, aliases de 32/64 bits, stack,
branches, recursos, fonte, recibos e contratos alterados. Um oráculo GAS confere
todas as 18 famílias de encoding do modelo e 2.944 combinações GPR de
registradores/larguras. Bytes malformados e 150 mutações determinísticas são
apenas analisados. Há testes de budget, FIFO, arquivo excessivo, JSON duplicado e
targets não autorizados pelo modelo.

O consumidor nativo executa somente os 17 bytes revisados de `max_u64.basm`,
depois de conferir seu valor literal, paridade GAS e aceitação pelo checker.
São 10.243 observações de resultados e preservação de RBX, incluindo bordas
unsigned e 10.000 pares determinísticos. Não são prova funcional universal.

O teste de publicação inclui mutação de `pop rbx` para `pop rcx`, com hash da
fonte atualizado: a recusa precisa vir de `CALLEE_SAVED`, não apenas de hash
antigo. Ele também confere que a geração anterior permanece selecionada,
alterações de contrato exigem nova aprovação e remover o recibo do manifesto
não satisfaz um consumidor que exige o contrato.

O custo do checker é externo à unity build. Não foi adicionada dependência de
Python ao caminho normal de montagem. Essa separação não elimina o custo do
pacote ou do processo auxiliar; o checker não apresenta aqui um ganho de performance
nem altera gates soberanos ou a ISA canônica do assembler.
