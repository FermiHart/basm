<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Publicação e consumo de gerações com contrato

`tools/publish_generation.py` é um comando externo opcional. Ele produz uma
geração com objeto e evidência, verifica suas obrigações e troca o arquivo
`current.json` que seleciona a geração. O assembler normal continua disponível
sem Python. O publicador não liga nem executa o objeto.

## Formatos e responsabilidade de cada camada

| Artefato | Formato | O que ele estabelece |
| --- | --- | --- |
| `object.o` | ELF64 AMD64 ET_REL | Bytes, símbolos e relocations usados como entrada dos verificadores |
| `object.basmproof` | A publicação solicita attestation v4 | Compromissos de montagem e vínculo com o hash do objeto, conferidos pelo verificador do assembler |
| Contrato externo | `bearbasm-contract-v1` | Função, ABI, clobbers, stack e requisitos que o consumidor permite |
| Target externo | `bearbasm-contract-target-v1` | Declaração de CPU/OS que o consumidor precisa estabelecer no ambiente real |
| `contract-result.json` | `bearbasm-contract-result-v1` | Resultado do checker independente sobre os bytes da função dentro do modelo fechado |
| `current.json` | `basm-generation-v1` | Nome de uma geração e caminhos, tamanhos e hashes dos seus membros |

**A assinatura da proof v4 não assina `contract-result.json` nem
`current.json`.** Os hashes de um manifesto que possa ser substituído não se
autenticam sozinhos. O campo `trust` registrado no manifesto também não concede
autoridade: a verificação calcula seu resultado conforme a chave externa que o
consumidor forneceu na invocação atual.

O comando `verify` confere os hashes dos membros, confere que a proof vincula
`output_sha256` e `output_format: elf64` ao objeto, e passa os mesmos bytes da
proof a uma cópia privada para o verificador do assembler. Sem `--trusted-key`,
o resultado tem `trust: integrity-only`. Com a chave externa, usa o verificador
estrito e retorna `trust: external-key-verified` somente após sua aceitação.

As operações `publish` e `verify` exigem o cabeçalho exato de v4 nos mesmos bytes
da proof cujo binding e assinatura serão verificados. Uma proof v2/v3 válida
não satisfaz esta política de geração, mesmo com assinatura, hashes e manifesto
coerentes. A CLI independente do assembler conserva sua compatibilidade com
v2/v3; esse comportamento não enfraquece o requisito do wrapper.

## Política de contrato do consumidor

Uma geração com `contract-result.json` requer `--contract` também durante
`verify`. O caso inverso é igualmente recusado: o consumidor que exige contrato
não aceita um manifesto do qual o recibo foi removido. O wrapper chama o checker
local adjacente ao seu próprio script, com os caminhos de contrato, fonte e
target explicitamente fornecidos pelo consumidor. É responsabilidade do
consumidor escolher uma instalação confiável dessas ferramentas e dessas
declarações.

Na verificação, o recibo guardado é passado por `--expect`: identidades de
checker/modelo, objeto, contrato, target, fonte e função são conferidas, e a
análise dos bytes é repetida. Um rótulo de aprovação fabricado não dispensa a
análise. Um invasor capaz de substituir toda a geração também pode substituir
um recibo não assinado; `--expect` não transforma esse recibo em autorização
externa nem em garantia de frescor.

O target é uma declaração, não uma leitura de CPUID, XCR0 ou configuração do
kernel. A fonte e seu mapa são pistas diagnósticas com identidade conferida;
não se prova a correspondência semântica fonte/bytes. `VERIFIED_WITHIN_MODEL`
estabelece somente as obrigações de ABI enumeradas em [MODEL.md](MODEL.md).
`functional_result` continua `NOT_CHECKED`, mesmo depois do sucesso do wrapper.

## Comandos

Os exemplos partem da raiz do repositório, com a lane host já construída. A
variável aponta para o binário que será efetivamente usado:

```sh
BASM_CANDIDATE="$PWD/build/host/basm"
python3 tools/publish_generation.py publish \
  --basm "$BASM_CANDIDATE" --root build/contract-demo/store \
  --source contracts/examples/max_u64.basm \
  --contract contracts/max_u64.json \
  --contract-target contracts/target-base.json
python3 tools/publish_generation.py verify \
  --basm "$BASM_CANDIDATE" --root build/contract-demo/store \
  --source contracts/examples/max_u64.basm \
  --contract contracts/max_u64.json \
  --contract-target contracts/target-base.json
```

O mesmo arquivo de target é usado nas duas operações. O target default é
semanticamente equivalente a `target-base.json`, mas seus bytes canônicos
internos têm identidade diferente de um arquivo JSON com outra formatação.
Mudar entre as duas representações invalida o recibo esperado.

Para proveniência com signatário externo, a publicação requer **ambas** as
opções `--sign` e `--trusted-key`. A verificação posterior requer somente a chave
pública:

```sh
python3 tools/publish_generation.py publish \
  --basm "$BASM_CANDIDATE" --root build/contract-demo/signed-store \
  --source contracts/examples/max_u64.basm \
  --contract contracts/max_u64.json \
  --sign /caminho/privado/publicador.seed \
  --trusted-key /caminho/confiavel/publicador.pub
python3 tools/publish_generation.py verify \
  --basm "$BASM_CANDIDATE" --root build/contract-demo/signed-store \
  --source contracts/examples/max_u64.basm \
  --contract contracts/max_u64.json \
  --trusted-key /caminho/confiavel/publicador.pub
```

Os caminhos de chave são exemplos que devem ser substituídos por arquivos
reais. Seed e chave pública usam arquivos de 32 bytes brutos ou 64 dígitos
hexadecimais, com whitespace final limitado pelo leitor. A chave pública é
selecionada pelo consumidor por um canal confiável externo ao artefato; não é
extraída da proof para conceder confiança à própria proof.

`--source` é obrigatório em `publish`; em `verify`, também é necessário quando
o contrato contém binding de fonte, como nos dois exemplos deste diretório.
`--contract-target` exige `--contract`. `--target-profile public|beyond` é uma
opção de montagem de `publish`, com default `public`; ela não muda o modelo
SysV hosted do checker nem atesta o target real.

O wrapper retorna JSON no stdout e exit code 0 para sucesso. Recusas normais
retornam exit code 1 com JSON no stderr. Erros de sintaxe da CLI seguem o
comportamento do `argparse`, com exit code 2 e mensagem textual; não devem ser
interpretados como resultados de verificação.

## Ponto de publicação e limites

A ordem é: montar em uma nova geração; verificar a proof; verificar o contrato,
se exigido; calcular os registros dos membros; sincronizar arquivos e diretórios;
substituir `current.json` por rename; sincronizar o diretório raiz. Falhas de
montagem, proof ou contrato anteriores ao rename preservam a seleção anterior.
O teste de integração troca `pop rbx` por `pop rcx` e atualiza o hash da fonte: a recusa
`CALLEE_SAVED` impede a troca do ponteiro e a geração malsucedida é removida.

O consumidor lê o ponteiro uma vez e trabalha com aquela geração. Os membros
recebem modo `0444` e o fluxo normal não os modifica depois do commit. Isso é
uma disciplina local de publicação; o proprietário pode alterar permissões e
reescrever os arquivos. Um escritor hostil com o mesmo UID, substituição de
diretórios pais e alterações entre verificação e uso permanecem fora desta
garantia. O deploy precisa controlar esses diretórios e o caminho até o uso.

Não há lock entre publicadores concorrentes; a última troca de ponteiro pode
selecionar uma geração completa diferente. Não há contador monotônico, expiração
ou prevenção de rollback de uma geração antiga ainda válida. Essas políticas
devem ser aplicadas pelo consumidor quando necessárias.

Rename local e chamadas de `fsync` não prometem comportamento universal em
filesystem de rede, controladores de armazenamento ou perda de energia. Se a
sincronização posterior ao rename falhar, a nova seleção já pode estar visível,
apesar de o comando terminar com erro. Isso difere de uma recusa do checker,
que acontece antes do ponto de publicação.

O manifesto é limitado a 16 KiB, a leitura da proof a 16 MiB e o cálculo de
hash dos membros a 1 GiB por artefato. A análise por contrato impõe seus limites
menores, incluindo objeto de 4 MiB e função de 4.096 bytes. O wrapper exige
membros regulares em caminhos restritos à geração. Ele não certifica a imagem
final ligada nem concede permissão para executar o objeto.
