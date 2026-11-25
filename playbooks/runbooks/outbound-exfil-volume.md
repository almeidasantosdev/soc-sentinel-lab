# Volume anômalo de saída para IP público

Regra: `detections/outbound-exfil-volume.yaml`  
MITRE: T1048, T1567  
Severidade: High

## Objetivo

Decidir se o volume enviado para um IP público é transferência autorizada ou saída de dados fora do combinado.

## SLA

- N1 inicia a triagem em 15 minutos após o incidente.
- Se o destino não estiver na lista de parceiros, escala para o N2 em 30 minutos.
- O relógio conta a partir da criação do incidente no Sentinel.

## Passos do N1

1. Anote origem, destino, porta, conta e total de bytes.
2. Confirme que a ação do firewall foi permissão, não negação.
3. Compare o destino com backup externo, atualização de software e parceiros.
4. Veja se a conta de origem é serviço de backup e se a janela bate com a agenda.
5. Procure, no mesmo host, compactação ou leitura em massa de arquivos sensíveis.
6. Se o destino for novo e o volume passar do limiar sem mudança aberta, escale.

## Falsos positivos

Backup externo, imagem de atualização e envio grande para parceiro já catalogado. O limiar de 100 MB é didático e fica baixo para uma rede real.

## Escalação para o N2

Escale quando o destino não tem dono, a conta não é a de backup ou a porta não é a do fluxo documentado. Entregue o total de bytes e o IP enriquecido.

## Contenção

O N1 não bloqueia o destino. O N2 pede o bloqueio na borda e a preservação do host se o destino continuar recebendo dados. Não apague o log do firewall.
