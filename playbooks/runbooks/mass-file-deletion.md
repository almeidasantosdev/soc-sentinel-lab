# Exclusão em massa de arquivos

Regra: `detections/mass-file-deletion.yaml`  
MITRE: T1485  
Severidade: High

## Objetivo

Descobrir se a conta apagou arquivos de propósito operacional ou se o volume indica destruição de dados.

## SLA

- N1 inicia a triagem em 15 minutos após o incidente.
- Se a pasta não for temporária e a conta não tiver tarefa de limpeza, escala para o N2 em 30 minutos.
- O relógio conta a partir da criação do incidente no Sentinel.

## Passos do N1

1. Confirme conta, computador e a amostra de caminhos no alerta.
2. Veja se os caminhos ficam em pasta temporária, lixeira ou diretório de negócio.
3. Procure tarefa agendada ou script de limpeza no mesmo computador e no mesmo minuto.
4. Verifique se a conta é de serviço e quem é o dono registrado.
5. Olhe o evento 4688 próximo: houve powershell ou ferramenta de compactação antes da exclusão?
6. Se os arquivos forem de área financeira ou de cliente, trate como impacto até prova em contrário.

## Falsos positivos

Rotação de backup, limpeza de temporários e desmontagem de projeto. O número de objetos distintos importa mais do que um único arquivo apagado várias vezes.

## Escalação para o N2

Escale quando o caminho for de negócio, a conta de serviço não tiver mudança aberta ou aparecer criptografia junto da exclusão. Entregue a amostra de caminhos e o dono da conta.

## Contenção

O N1 não apaga a conta nem restaura arquivo. O N2 aciona o dono do servidor para preservar volume e, se preciso, isolar o host. Restauração segue o procedimento de backup da empresa.
