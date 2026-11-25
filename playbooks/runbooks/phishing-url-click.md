# Clique permitido em URL de phishing

Regra: `detections/phishing-url-click.yaml`  
MITRE: T1566, T1566.002  
Severidade: Medium

## Objetivo

Verificar se a pessoa clicou num link suspeito que o controle deixou passar e se houve entrada ou download em seguida.

## SLA

- N1 inicia a triagem em 60 minutos após o incidente.
- Se a conta teve entrada anômala depois do clique, escala para o N2 em 4 horas.
- O relógio conta a partir da criação do incidente no Sentinel.

## Passos do N1

1. Abra a URL, o domínio e a conta. Não cole a URL em um navegador comum.
2. Confirme que a ação foi `ClickAllowed`. Clique bloqueado fica para a caçada, não para esta regra.
3. Veja a mensagem de origem pelo `NetworkMessageId` e quem mais recebeu o mesmo link.
4. Procure entradas da conta nos 30 minutos seguintes, principalmente de IP novo.
5. Pergunte ao usuário se ele esperava aquele domínio.
6. Se o domínio imita marca conhecida e o usuário não reconhece, escale com a URL completa.

## Falsos positivos

Campanha legítima em TLD genérico, ferramenta nova e encurtador interno. A lista de TLDs e de imitações deste laboratório é didática, não um feed de reputação.

## Escalação para o N2

Escale quando houver credencial digitada, anexo aberto ou entrada nova depois do clique. Entregue a URL, o horário e o resultado da conversa com o usuário.

## Contenção

O N1 não desativa a caixa. O N2 pode revogar sessão e pedir troca de senha se o usuário informou credencial. Bloqueio do domínio segue o processo de correio.
