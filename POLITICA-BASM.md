# Política do dialeto `.basm`

**Status:** normativa. Define a compatibilidade do dialeto e os critérios para
alterar seu comportamento. O contrato de sintaxe, formatos e instruções está
em [SUPPORTED-SUBSET.md](SUPPORTED-SUBSET.md).

## 1. Escopo e perfis

Basm implementa um subconjunto da sintaxe NASM para objetos ELF64 x86-64 e
binários planos, com extensões explícitas. Não promete compatibilidade com
todas as instruções, operandos ou diretivas do NASM.

O executável público usa somente o modo de codificação de 64 bits e não admite
o bootstrap AP. `basm-compat` preserva a interface de compatibilidade e permite
selecionar os perfis `public` ou `beyond`. A exceção `ap-trampoline-v1` pertence
apenas ao perfil Beyond e exige a identidade exata da fonte registrada. O nome
de um perfil não constitui autorização de execução nem prova semântica.

Cada forma de linguagem pertence a uma destas classes:

| Classe | Definição | Critério |
|---|---|---|
| Paridade | Aceita por Basm e NASM | Mesmos observáveis definidos abaixo |
| Extensão | Semântica específica de Basm | Contrato explícito e teste dedicado |
| Proibida | Fora do subconjunto declarado | Erro claro, sem reinterpretação silenciosa |

## 2. Paridade diferencial

Uma fonte da classe Paridade deve produzir `.text` byte a byte idêntico ao NASM,
símbolos normalizados idênticos e relocações idênticas. Offsets de arquivo,
padding e tabelas de strings podem diferir quando não alteram esses observáveis.
Binários planos são comparados integralmente, byte a byte.

Use o NASM como oráculo externo e `elftool diff` para as comparações normalizadas
de objetos. Inspeções auxiliares devem declarar suas ferramentas e limites.
Uma divergência não pode ser convertida em aprovação por remover o caso do teste.

## 3. Extensões e recusas

Uma extensão deve preservar o significado das fontes já aceitas, ter sintaxe e
limites documentados, produzir resultados determinísticos para as entradas e
configurações declaradas e possuir testes positivos e negativos. Objetos gerados
devem passar pelas verificações estruturais aplicáveis de `elftool audit`.

A classificação deve constar em `tests/encoding_subset_allowlist.txt` quando
aplicável ao corpus de cobertura. A recusa do NASM, sozinha, não autoriza uma
extensão nem um SKIP. Diretivas com nomes comuns, como `%ifdef`, labels locais
e `istruc`, precisam de classificação pela forma e semântica exatas.

Uma entrada proibida deve falhar de forma controlada. Quando houver saídas
anteriores, a recusa deve preservar esses arquivos conforme o contrato de
publicação. Os testes precisam distinguir erro de entrada, falha de escrita,
crash e corrupção de resultado.

## 4. Evidência e confiança

A emissão de attestation é opcional. `--emit-attestation` produz v2 na interface
de compatibilidade sem seletor e v3 nos perfis explícitos. O executável público
já seleciona o perfil `public`. `--emit-attestation-v4` acrescenta os registros
de insumos consumidos e o digest da fonte expandida, exigindo um perfil explícito.

`--sign` permite assinar a evidência com Ed25519. Verificação estrita exige uma
assinatura; a identidade do signatário só é vinculada à política do consumidor
quando uma chave pública confiável é fornecida por `--trusted-key`.

`elftool attest` recalcula os hashes dos arquivos registrados, verifica as
assinaturas presentes e as ligações entre provas fornecidas. `--tool` permite
vincular a primeira prova a um executável fornecido pelo consumidor. Os arquivos
referidos precisam continuar acessíveis nos caminhos registrados.

A prova de um objeto não cobre automaticamente o executável resultante de uma
linkedição. Assinatura, digest, explicação e CFG parcial não provam correção
semântica, segurança de memória ou contenção em execução. O trailer PQC opcional
é um placeholder e não oferece segurança pós-quântica.

## 5. Plataformas e mudanças

Linux x86-64 é o alvo da distribuição binária atual. Adaptações de fonte para
outros hosts não equivalem a uma plataforma qualificada. Testes que dependem de
loader ELF Linux ou de componentes Beyond devem declarar essa dependência.

Uma mudança de comportamento requer um reproduzidor, a classificação de
paridade/extensão/recusa, testes focados e atualização deste contrato quando
necessária. `make check` executa a suíte standalone documentada em
[docs/TESTING.md](docs/TESTING.md); testes de integração adicionais conservam
seu próprio escopo. Falhas, indisponibilidade e testes não executados devem
permanecer explícitos no resultado.

---

Autor: F E R M I ∞ H A R T <contact@fermihart.com>
SPDX-License-Identifier: Unlicense
