# Entrada externa negada em porta administrativa

Regra: `detections/suspicious-admin-port-inbound.yaml`  
MITRE: T1133, T1021, T1021.001  
Severidade: Medium

## Objetivo

Separar varredura externa contra porta administrativa de um scanner ou de uma regra de firewall que a operação já espera.

## SLA

- N1 inicia a triagem em 60 minutos após o incidente.
- Se o destino for servidor sensível e a origem for desconhecida, escala para o N2 em 4 horas.
- O relógio conta a partir da criação do incidente no Sentinel.

## Passos do N1

1. Anote IP de origem, IP de destino, portas e quantidade de tentativas.
2. Confirme no firewall se a ação foi mesmo negação, não permissão.
3. Consulte o inventário: o destino expõe RDP, SSH ou WinRM de propósito?
4. Compare a origem com scanners de vulnerabilidade e monitoração externa.
5. Veja se o mesmo IP teve permissão em outra regra na mesma hora.
6. Se a origem for pública e o destino for servidor interno, mantenha o incidente aberto.

## Falsos positivos

Scanner autorizado, sonda do próprio firewall e teste de mudança em janela combinada. O limiar de cinco tentativas é ponto de partida de laboratório.

## Escalação para o N2

Escale se houver permissão posterior, destino de administração de domínio ou origem reincidente no dia. Entregue as portas e o trecho do log CEF.

## Contenção

Não abra a porta e não bloqueie a origem sem o dono do firewall. O N2 pede o bloqueio na borda se a origem não tiver justificativa. O playbook só enriquece o IP e avisa.
