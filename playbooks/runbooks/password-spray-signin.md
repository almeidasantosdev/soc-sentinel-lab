# Password spray em entradas do Entra ID

Regra: `detections/password-spray-signin.yaml`  
MITRE: T1110, T1110.003  
Severidade: High

## Objetivo

Descobrir se um único IP testou senha em muitas contas para não estourar o bloqueio de uma identidade só.

## SLA

- N1 inicia a triagem em 15 minutos após o incidente.
- Se não houver falso positivo documentado, escala para o N2 em 30 minutos.
- O relógio conta a partir da criação do incidente no Sentinel.

## Passos do N1

1. Anote o IP, a quantidade de contas e a amostra de usuários no alerta.
2. Confira se as falhas usam o mesmo aplicativo e o mesmo código de resultado.
3. Veja se alguma dessas contas teve sucesso a partir desse IP na mesma janela.
4. Compare o IP com NAT corporativo, provedor de identidade federado e scanner autorizado.
5. Se várias contas sem relação falharam juntas, trate como spray e não como erro isolado de usuário.
6. Liste as contas privilegiadas que aparecem na amostra e marque prioridade.

## Falsos positivos

Troca de senha em massa no mesmo NAT, portal de autoatendimento e laboratório de autenticação. O volume de contas distintas é o que separa este caso de uma força bruta contra uma pessoa só.

## Escalação para o N2

Escale se houver sucesso no IP suspeito, conta privilegiada na lista ou origem fora do inventário. Entregue a lista de contas, o IP enriquecido e os horários.

## Contenção

Não desative todas as contas do alerta. O N2 escolhe revogação de sessão e reset só para quem teve sucesso suspeito ou é administrador. As demais entram em observação.
