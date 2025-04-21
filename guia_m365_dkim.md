# Guia para habilitar DKIM no Microsoft 365

Este guia apresenta os passos detalhados para habilitar a assinatura DKIM em domínios vinculados ao Microsoft 365.

## O que é DKIM?

DKIM (DomainKeys Identified Mail) é um método de autenticação de email que permite ao servidor receptor verificar se uma mensagem foi realmente enviada pela organização proprietária do domínio e se o conteúdo da mensagem não foi alterado durante o trânsito.

## Pré-requisitos

1. Acesso administrativo ao [Centro de administração do Microsoft 365](https://admin.microsoft.com)
2. Acesso ao seu provedor de DNS para adicionar os registros CNAME necessários
3. Seu domínio já deve estar configurado no Microsoft 365

## Passo 1: Verificar o estado atual do DKIM

1. Acesse o [Centro de administração do Exchange](https://admin.exchange.microsoft.com)
2. Navegue até **Proteção** > **DKIM**
3. Você verá a lista de domínios configurados e o status do DKIM para cada um

## Passo 2: Obter os registros CNAME necessários

Antes de habilitar o DKIM, você precisa adicionar dois registros CNAME ao DNS do seu domínio. Para cada domínio, o Microsoft 365 requer dois registros CNAME:

| Nome do host (Host name) | Aponta para (Points to) | TTL |
|--------------------------|-------------------------|-----|
| selector1._domainkey | selector1-{domain-GUID}._domainkey.{tenant-name}.onmicrosoft.com | 3600 (ou padrão) |
| selector2._domainkey | selector2-{domain-GUID}._domainkey.{tenant-name}.onmicrosoft.com | 3600 (ou padrão) |

Onde:
- `{domain-GUID}` é um identificador único gerado para o seu domínio (geralmente seu domínio com os pontos substituídos por hífens)
- `{tenant-name}` é o nome do seu tenant Microsoft 365 (a parte antes de .onmicrosoft.com)

## Passo 3: Adicionar os registros CNAME ao seu DNS

Dependendo do seu provedor de DNS, os passos podem variar. Aqui está um exemplo geral:

1. Faça login no seu provedor de DNS
2. Acesse a configuração de zona do seu domínio
3. Adicione os dois registros CNAME conforme indicado pelo Microsoft 365
4. Salve as alterações

**Exemplo para o domínio exemplo.com.br**:

```
selector1._domainkey.exemplo.com.br  CNAME  selector1-exemplo-com-br._domainkey.exemploms.onmicrosoft.com
selector2._domainkey.exemplo.com.br  CNAME  selector2-exemplo-com-br._domainkey.exemploms.onmicrosoft.com
```

> **Nota**: Os valores exatos dos registros CNAME variam para cada tenant e devem ser obtidos no Centro de Administração do Exchange.

## Passo 4: Habilitar o DKIM no Microsoft 365

1. Volte ao [Centro de administração do Exchange](https://admin.exchange.microsoft.com)
2. Navegue até **Proteção** > **DKIM**
3. Selecione seu domínio na lista
4. Clique em **Habilitar**
5. Confirme a ação

## Passo 5: Verificar se o DKIM está funcionando

O Microsoft 365 pode levar de 24 a 48 horas para detectar os registros CNAME e começar a assinar emails com DKIM. Você pode verificar se está funcionando:

1. Enviando um email de teste para uma conta externa (como Gmail)
2. Verificando os cabeçalhos do email recebido
3. Procurando por `dkim=pass` nos resultados de autenticação

Ou use o script email_auth_fix.py deste projeto para verificar a configuração:

```bash
python email_auth_fix.py exemplo.com.br -v
```

## Resolução de problemas

### Os registros CNAME foram adicionados, mas o DKIM não está habilitando

- Verifique se os registros CNAME estão exatamente como especificados pelo Microsoft 365
- Aguarde até 48 horas para a propagação DNS completa
- Verifique se não há erros de sintaxe nos registros CNAME

### O DKIM está habilitado, mas os emails ainda falham na autenticação DKIM

- Verifique se os emails estão realmente sendo enviados pelo Microsoft 365
- Certifique-se de que seu domínio está configurado como domínio aceito no Microsoft 365
- Verifique se não há regras de transporte que possam modificar os cabeçalhos dos emails

### O DKIM está habilitado apenas para um seletor

O Microsoft 365 usa um sistema de rotação de chaves DKIM (alternando entre selector1 e selector2). É essencial ter ambos os seletores configurados para um funcionamento adequado.

## Recursos adicionais

- [Configurar DKIM para um domínio personalizado no Microsoft 365](https://learn.microsoft.com/pt-br/microsoft-365/security/office-365-security/email-authentication-dkim-configure)
- [Solucionar problemas com DKIM](https://learn.microsoft.com/pt-br/microsoft-365/security/office-365-security/email-authentication-dkim-configure?view=o365-worldwide#troubleshooting-dkim)
- [Como o Microsoft 365 usa DKIM para validar emails](https://learn.microsoft.com/pt-br/microsoft-365/security/office-365-security/email-authentication-dkim-configure?view=o365-worldwide#how-dkim-works-with-microsoft-365) 