<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Modelo x86-64-sysv-leaf-v1

## Propriedade estabelecida

Para uma entrada exatamente no início da função global STT_FUNC selecionada,
todo caminho do grafo acíclico conservador chega a um RET com:

1. RSP igual ao valor de entrada;
2. RBX, RBP e R12–R15 iguais aos valores completos de 64 bits da entrada;
3. DF clear, como exige a precondição de entrada SysV;
4. alteração de estado caller-saved contida na lista `clobbers`;
5. uso de slots de stack limitado ao orçamento declarado.

Cada condição é relativa à semântica enumerada abaixo. A análise não é uma
formalização completa de x86 ou uma prova mecanizada da implementação Python.
Os testes independentes reduzem risco de erro no checker, mas não substituem
revisão de seu modelo e código por quem lhe concede confiança.

## Precondições

- Long mode, ABI SysV AMD64, execução hosted em userspace.
- RSP de entrada congruente a 8 módulo 16, apontando a endereço de retorno válido
  e confiável. DF inicialmente clear.
- A quantidade declarada/usada de bytes abaixo de RSP pertence à stack privada,
  é legível/escrevível e não se sobrepõe a estado que outro ator possa modificar.
- CPU/OS satisfazem o target declarado pelo consumidor. O checker não observa
  hardware, XCR0, permissões atuais nem configuração de CPUID faulting.
- Não há alteração assíncrona do código, stack, registradores salvos ou ambiente.
- A ligação preserva os bytes da função e o consumidor entra pelo símbolo
  conferido. Não há certificação pós-link, CFI global ou garantia sobre callers.

Essas condições não podem ser inferidas de uma assinatura do objeto. Stack
inválida ou requisitos reais diferentes podem causar faults mesmo quando a ABI
do recorte foi verificada.

## Região ELF aceita

ELF64 little-endian x86-64 ET_REL, com identificação System V ou Linux, sem
program headers, uma SYMTAB e extents explícitos. Não há extended section indices,
compressão, TLS, COMDAT/group ou relocations dinâmicas neste modelo. As seções de
arquivo devem caber integralmente no input e não podem sobrepor headers ou outras
seções com conteúdo. NOBITS não causa alocação proporcional a seu tamanho.

O checker valida nomes limitados, tipos/bindings, links de tabelas, divisão
local/global, extents de símbolos e ranges de RELA. Reconhece estruturalmente
R_X86_64_64, PC32, 32 e 32S. **Qualquer relocation que toque a função selecionada
bloqueia a prova**, pois os bytes finais ainda não são conhecidos. Não é feito
matching semântico entre contratos de diferentes objetos.

A função deve ter binding GLOBAL, tipo FUNC, tamanho de 1 a 4.096 bytes e estar
em PROGBITS com ALLOC+EXEC e sem WRITE. O resultado refere-se só a essa região.
Outra função, dados ou instruções em outra parte do objeto não recebem o mesmo
veredicto. O hash do objeto inteiro preserva a identidade do recipiente.

## Inventário de instruções

`tools/contract_check.py:FORMS` é a autoridade do decoder independente. O arquivo
`instruction-forms-v1.json` é a exportação por `--describe`, conferida pelo teste.
Ele não modifica nem substitui `isa/forms.tsv` do assembler.

| Família | Semântica no recorte |
| --- | --- |
| MOV RR, 32/64 bits | ModRM mod=3; papéis concretos dst/src e REX.R/B; cópia de proveniência só para largura 64 |
| ADD/SUB/XOR RR, 32/64 bits | Destino torna-se desconhecido; flags passam a clobber conservador |
| CMP/TEST RR, 32/64 bits | Preservam registradores; flags passam a clobber conservador |
| PUSH/POP de GPR 64 | Stack privada de slots de oito bytes, guardando/restaurando proveniência |
| ADD/SUB RSP com immediate | Immediate signed não negativo, múltiplo de oito; no máximo 512 bytes por ajuste |
| JMP rel8/rel32 | Alvo interno em início decodificado de instrução, estritamente para frente |
| Jcc rel8/rel32 | Todos os 16 condition codes; ambos os sucessores são explorados |
| NOP, RET | Continuação ou obrigação de retorno |
| CLD, STD | Estado explícito de DF; STD precisa ser compensado antes de RET |
| CPUID | Desconhece RAX/RBX/RCX/RDX; exige CPU feature cpuid e CPUID userspace habilitado |

São **18 famílias de encoding**, não cobertura geral de 18 mnemonics ou de toda
x86. Direções de opcodes RR admitidas aparecem no inventário. REX.X redundante
com mod=3 e prefixes não especificados são recusados. Escrever ESP/RSP por MOV ou
aritmética geral e POP RSP não é modelado. Ler RSP é permitido; sua proveniência
acompanha o delta de stack. Memória explícita, CALL, RET immediate, indireções,
loops, SIMD, instruções de privilégio e instruções desconhecidas bloqueiam prova.

Uma escrita em EBX invalida a preservação do RBX inteiro, mesmo `mov ebx,ebx`:
ela zera os 32 bits superiores. Uma cópia `mov rbx,rbx` de 64 bits preserva a
proveniência. O modelo não tenta recuperar igualdades aritméticas sofisticadas;
funções corretas podem ser recusadas de modo conservador.

## Análise de estado

O estado guarda proveniência de 16 GPRs, delta de RSP, valores dos slots privados,
DF e se houve clobber conservador de flags. Proveniência inicial é distinta por
registrador. MOV64 e PUSH/POP copiam a proveniência exata. Escritas aritméticas e
parciais produzem valores desconhecidos que não equivalem à origem de um
registrador preservado.

PUSH escreve um slot abaixo da stack atual. POP só lê slot previamente escrito
e ainda pertencente à frame. Reservar espaço por SUB não inicializa o slot;
POP dessa reserva é recusado, mesmo quando a função pudesse ser aceita por um
modelo de memória mais amplo. ADD pode liberar slots, mas não atravessar o
endereço de retorno de entrada. Nenhuma forma permitida escreve diretamente no
endereço de retorno.

Os bytes de toda a região são decodificados, inclusive os de regiões que podem
ser inalcançáveis. Não há identificação heurística de dados como instruções
seguras. Alvos no meio da instrução ou fora da região são rejeitados. Backedges
são `UNPROVEN`, pois exigiriam invariantes de loop ou prova de terminação.

Em cada branch, o checker explora os dois lados sem resolver o valor das flags.
Isso inclui caminhos inviáveis, de maneira conservadora. Estados idênticos são
memoizados. Se um retorno viola a ABI, a saída inclui o caminho concreto do
grafo abstrato que levou à violação; ele pode ser inviável para o programa real,
e portanto a conclusão é sobre a incapacidade de satisfazer este modelo fechado.

## Orçamentos e recusas

| Recurso | Limite fixo |
| --- | ---: |
| Objeto | 4 MiB |
| Contrato / target / fonte / recibo | 64 KiB / 16 KiB / 1 MiB / 1 MiB |
| Seções / símbolos / relocations | 128 / 16.384 / 16.384 |
| Função | 4.096 bytes |
| Instruções / estados / passos | 512 / 512 / 2.048 |
| Stack privada | 512 bytes |
| Profundidade de JSON | 12 |

Arquivos são abertos uma vez, com leitura limitada, e devem ser regulares. Não
há stdin ilimitado, busca de includes, rede, execução de comandos ou caminhos
de input obtidos de metadata. A checagem stat antes/depois detecta substituição
concorrente comum, sem pretensão de snapshot contra um filesystem hostil.

Limite de análise esgotado, instrução desconhecida, loop ou requisito não
estabelecido retorna `UNPROVEN`, exit code 1. Falha estrutural ou violação do
contrato/modelo retorna `REJECTED`, também exit code 1. Não se publica resultado
parcial aprovado. O contrato não pode aumentar esses limites.

## Evidência e política

O resultado identifica schema, modelo, bytes do checker, inventário de formas,
objeto, contrato, fonte, target e extensão da função. Ele separa verificação de
ABI de requisitos conferidos apenas contra um target declarado. `--expect`
confere as identidades e reexecuta a análise; `--compare-contracts` compara
declarações e não aprova execução.

O mapa de fonte não é derivação semântica. O target não é atestação de hardware.
O recibo não é assinatura institucional. A proof v4 que o publicador emite não
assina o recibo do checker nem o manifesto da geração. Um consumidor seguro
fornece sua política e ferramenta externa, verifica a proveniência que exigir e
refaz o checker sobre os bytes recebidos antes de conceder qualquer autoridade.
