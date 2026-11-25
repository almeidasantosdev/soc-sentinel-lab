# Força bruta em entradas do Entra ID

Regra: `detections/brute-force-signin.yaml`  
MITRE: T1110, T1110.001  
Severidade: High

## Objetivo

Confirmar se as falhas concentradas em uma conta e um IP são tentativa de adivinhação de senha ou um cliente legítimo com credencial desatualizada.

## SLA

- N1 inicia a triagem em 15 minutos após o incidente.
- Se não houver falso positivo documentado, escala para o N2 em 30 minutos.
- O relógio conta a partir da criação do incidente no Sentinel.

## Passos do N1

1. Abra o incidente e confirme conta, IP, quantidade de falhas e aplicativos no detalhe do alerta.
2. No `SigninLogs`, veja se a mesma conta teve sucesso depois, de qual IP e de qual local.
3. Compare o IP com VPN, proxy e faixa de saída conhecidos da empresa.
4. Verifique se o usuário abriu chamado de senha no mesmo intervalo.
5. Se o IP for desconhecido e não houver sucesso legítimo, registre o horário da primeira e da última falha.
6. Avise o dono da conta por um canal já usado pela operação. Não peça a senha.

## Falsos positivos

Senha digitada errada várias vezes, aplicativo móvel com senha antiga e teste de um integrador conhecido. Sucesso posterior a partir do IP habitual da pessoa reduz a urgência, mas não apaga o registro.

## Escalação para o N2

Escale quando o IP não estiver no inventário, a conta for privilegiada ou houver sucesso a partir do IP suspeito. Entregue a consulta, os dois IPs comparados e o horário do último sucesso.

## Contenção

O N1 não bloqueia a conta. O N2 decide reset de senha, revogação de sessão ou bloqueio temporário, com registro da aprovação. O playbook deste repositório só enriquece IP e avisa o plantão.
