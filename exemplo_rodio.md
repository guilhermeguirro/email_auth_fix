# Exemplo de Diagnóstico: rodio.tec.br

## Análise de Autenticação de Email

Data da análise: 21/04/2023

### Email Analisado
```
From: Janaína Neto <janaina.neto@rodio.tec.br>
To: cliente@exemplo.com.br
Subject: Proposta Comercial - Ródio Tech Soluções
```

### Diagnóstico de Cabeçalho

#### Problemas Encontrados (3)
- Falha de SPF: fail (google.com: domain of janaina.neto@rodio.tec.br does not designate 2a01:111:f403:c003::5 as permitted sender)
- DKIM não encontrado nos cabeçalhos
- Falha de DMARC: fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE)

## Análise DNS

### Registros Atuais

#### SPF
```
rodio.tec.br. IN TXT "v=spf1 include:_spf.google.com -all"
```

#### DKIM
```
(Nenhum registro DKIM encontrado para Microsoft 365)
```

#### DMARC
```
_dmarc.rodio.tec.br. IN TXT "v=DMARC1; p=quarantine; rua=mailto:ti@rodio.tec.br"
```

### Causa dos Problemas

1. **Problema SPF**: O registro SPF está configurado apenas para Google Workspace, mas os emails estão sendo enviados pelo Microsoft 365 (outlook.com)
   
2. **Problema DKIM**: Não há registros DKIM configurados para os seletores do Microsoft 365 (selector1 e selector2)
   
3. **Problema DMARC**: Embora exista um registro DMARC, ele está falhando porque tanto SPF quanto DKIM estão falhando

## Solução Recomendada

### 1. Atualizar Registro SPF

#### Registro atual (incorreto):
```
v=spf1 include:_spf.google.com -all
```

#### Novo registro (correto):
```
v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all
```

> **Observação**: Mantivemos a configuração do Google caso ainda utilize-o para alguns serviços, mas adicionamos o Microsoft 365.

### 2. Adicionar Registros DKIM

```
selector1._domainkey.rodio.tec.br. CNAME selector1-rodio-tec-br._domainkey.rodiotech.onmicrosoft.com.
selector2._domainkey.rodio.tec.br. CNAME selector2-rodio-tec-br._domainkey.rodiotech.onmicrosoft.com.
```

### 3. Melhorar Registro DMARC

#### Registro atual:
```
v=DMARC1; p=quarantine; rua=mailto:ti@rodio.tec.br
```

#### Registro recomendado:
```
v=DMARC1; p=quarantine; pct=100; rua=mailto:ti@rodio.tec.br; ruf=mailto:ti@rodio.tec.br; fo=1
```

## Comandos de Implementação

### Para Azure/Office 365 (PowerShell)

```powershell
# Atualizar SPF
Add-DnsServerResourceRecord -ZoneName "rodio.tec.br" -Name "@" -Txt -DescriptiveText "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all" -TimeToLive 01:00:00

# Configurar DKIM
New-DkimSigningConfig -DomainName "rodio.tec.br" -Enabled $true -KeySize 2048 -Selector1 "selector1._domainkey.rodio.tec.br"
New-DkimSigningConfig -DomainName "rodio.tec.br" -Enabled $true -KeySize 2048 -Selector2 "selector2._domainkey.rodio.tec.br"

# Atualizar DMARC
Add-DnsServerResourceRecord -ZoneName "rodio.tec.br" -Name "_dmarc" -Txt -DescriptiveText "v=DMARC1; p=quarantine; pct=100; rua=mailto:ti@rodio.tec.br; ruf=mailto:ti@rodio.tec.br; fo=1" -TimeToLive 01:00:00
```

### Para BIND9 (Formato de Zona)

```
rodio.tec.br. IN TXT "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all"
selector1._domainkey.rodio.tec.br. IN CNAME selector1-rodio-tec-br._domainkey.rodiotech.onmicrosoft.com.
selector2._domainkey.rodio.tec.br. IN CNAME selector2-rodio-tec-br._domainkey.rodiotech.onmicrosoft.com.
_dmarc.rodio.tec.br. IN TXT "v=DMARC1; p=quarantine; pct=100; rua=mailto:ti@rodio.tec.br; ruf=mailto:ti@rodio.tec.br; fo=1"
```

## Conclusão

Após implementar as recomendações acima, os emails enviados pelo Microsoft 365 da Ródio Tech Soluções serão autenticados corretamente, evitando problemas de entrega e classificação como spam. 

A configuração também fornecerá:
- Proteção contra falsificação de e-mails (spoofing)
- Melhoria na reputação do domínio
- Monitoramento de tentativas de uso indevido através de relatórios DMARC

## Próximos Passos

1. Implementar as alterações DNS recomendadas
2. Habilitar DKIM no Centro de Administração do Microsoft 365
3. Monitorar relatórios DMARC para verificar a eficácia
4. Após 2-4 semanas de funcionamento correto, considerar atualizar a política DMARC para "p=reject" 