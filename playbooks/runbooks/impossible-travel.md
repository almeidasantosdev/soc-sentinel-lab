# Viagem impossível em entrada bem-sucedida

Regra: `detections/impossible-travel.yaml`  
MITRE: T1078, T1078.004  
Severidade: Medium

## Objetivo

Decidir se duas entradas bem-sucedidas em locais diferentes, num intervalo curto, são uso legítimo de VPN ou acesso com credencial válida.

## SLA

- N1 inicia a triagem em 60 minutos após o incidente.
- Se o segundo acesso não tiver explicação, escala para o N2 em 4 horas.
- O relógio conta a partir da criação do incidente no Sentinel.

## Passos do N1

1. Leia os dois locais, os dois IPs e o intervalo em minutos no alerta.
2. Confirme no `SigninLogs` o aplicativo, o user agent e se o acesso passou por VPN conhecida.
3. Pergunte ao usuário, pelo canal oficial, se ele reconhece os dois acessos.
4. Veja se a conta tem viagem ou mudança de país registrada no período.
5. Se só o segundo IP for desconhecido e o usuário não reconhecer, preserve os horários e escale.
6. Não conclua só pelo nome do país: o campo Location pode refletir o ponto de presença.

## Falsos positivos

VPN, saída de nuvem e celular que troca de país rápido. Também acontece quando o provedor registra o local do proxy, não o da pessoa.

## Escalação para o N2

Escale quando o usuário não reconhecer o acesso, a conta for privilegiada ou o segundo IP já aparecer em outra regra. Entregue os dois eventos lado a lado.

## Contenção

O N1 não revoga sessão. O N2 pode encerrar sessões e exigir novo fator se o usuário negar o acesso. Registre a resposta da pessoa no incidente.
