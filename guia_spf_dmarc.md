# Guia para configuração de SPF e DMARC no Microsoft 365

Este guia apresenta as melhores práticas para configurar SPF e DMARC corretamente para domínios que utilizam o Microsoft 365/Exchange Online.

## Configurando SPF

### O que é SPF?

SPF (Sender Policy Framework) é um mecanismo de validação de email que permite aos proprietários de domínios especificar quais servidores têm permissão para enviar emails em nome do domínio.

### Configuração básica de SPF para Microsoft 365

Para domínios que utilizam apenas o Microsoft 365, o registro SPF recomendado é:

```
v=spf1 include:spf.protection.outlook.com -all
```

Este registro deve ser adicionado como um registro TXT para o domínio base (exemplo.com.br).

### Explicação das partes do registro SPF:

- `v=spf1`: Versão do SPF
- `include:spf.protection.outlook.com`: Inclui todos os servidores do Microsoft 365 como remetentes autorizados
- `-all`: Política rigorosa - qualquer servidor não listado não está autorizado a enviar emails em nome do domínio

### Configuração de SPF para domínios com múltiplos serviços

Se você usa outros serviços para enviar emails (como Mailchimp, SendGrid, etc.), combine-os no mesmo registro SPF:

```
v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net include:sendgrid.net -all
```

### Problemas comuns com SPF no Microsoft 365

1. **Múltiplos registros SPF**: Um domínio deve ter exatamente um registro SPF. Múltiplos registros causam falhas.
2. **Uso de `?all` ou `~all`**: Estas são políticas mais permissivas e menos seguras que `-all`.
3. **Registro SPF muito longo**: O SPF tem um limite de 10 mecanismos de consulta DNS (lookups).
4. **Esquecimento do include do Microsoft 365**: Sem `include:spf.protection.outlook.com`, os emails enviados pelo Microsoft 365 falharão na autenticação SPF.

## Configurando DMARC

### O que é DMARC?

DMARC (Domain-based Message Authentication, Reporting & Conformance) é um mecanismo de validação de email que utiliza SPF e DKIM para determinar a autenticidade de um email.

### Configuração básica de DMARC para Microsoft 365

Registro DMARC inicial recomendado (modo monitoramento):

```
v=DMARC1; p=none; rua=mailto:dmarc-reports@exemplo.com.br; ruf=mailto:dmarc-reports@exemplo.com.br; fo=1
```

Este registro deve ser adicionado como um registro TXT para o subdomínio `_dmarc.exemplo.com.br`.

### Evolução gradual da política DMARC:

1. **Fase de monitoramento** (2-4 semanas):
   ```
   v=DMARC1; p=none; rua=mailto:dmarc-reports@exemplo.com.br; fo=1
   ```

2. **Fase de quarentena parcial** (2-4 semanas):
   ```
   v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc-reports@exemplo.com.br; fo=1
   ```

3. **Aumento gradual da quarentena** (aumentar o pct gradualmente):
   ```
   v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc-reports@exemplo.com.br; fo=1
   ```

4. **Quarentena total** (2-4 semanas):
   ```
   v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@exemplo.com.br; fo=1
   ```

5. **Política de rejeição** (configuração final ideal):
   ```
   v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@exemplo.com.br; fo=1
   ```

### Explicação das partes do registro DMARC:

- `v=DMARC1`: Versão do DMARC
- `p=none/quarantine/reject`: Política a ser aplicada (monitorar/colocar em quarentena/rejeitar)
- `pct=XX`: Porcentagem de mensagens sujeitas à política DMARC
- `rua=mailto:email@dominio.com`: Endereço para receber relatórios agregados
- `ruf=mailto:email@dominio.com`: Endereço para receber relatórios forenses (detalhados)
- `fo=1`: Gerar relatórios forenses se SPF ou DKIM falhar

### Problemas comuns com DMARC no Microsoft 365

1. **Nunca sair do modo `p=none`**: Muitas organizações não evoluem além do modo de monitoramento.
2. **Pular diretamente para `p=reject`**: Implementar a política mais rigorosa sem uma fase de transição pode causar perda de emails legítimos.
3. **Não monitorar os relatórios DMARC**: Os relatórios são essenciais para identificar fontes legítimas de email que precisam ser autorizadas.
4. **Não configurar DKIM**: DMARC funciona melhor quando tanto SPF quanto DKIM estão ativos e funcionando.

## Verificando a configuração

Após configurar SPF e DMARC, você pode verificar se estão funcionando corretamente usando:

1. **O script deste projeto**:
   ```bash
   python email_auth_fix.py exemplo.com.br -v
   ```

2. **Ferramentas online**:
   - [MXToolbox](https://mxtoolbox.com/SuperTool.aspx)
   - [DMARC Analyzer](https://www.dmarcanalyzer.com/dmarc-checker/)
   - [mail-tester.com](https://www.mail-tester.com/)

3. **Verificação manual**:
   - Envie um email de teste para uma conta Gmail
   - Visualize o cabeçalho completo do email
   - Verifique se aparece `spf=pass` e `dmarc=pass`

## Recursos adicionais

- [Melhores práticas para SPF no Microsoft 365](https://learn.microsoft.com/pt-br/microsoft-365/security/office-365-security/email-authentication-spf-configure)
- [Guia completo de DMARC](https://learn.microsoft.com/pt-br/microsoft-365/security/office-365-security/email-authentication-dmarc-configure)
- [Como o Microsoft usa DMARC para proteção contra spoofing](https://learn.microsoft.com/pt-br/microsoft-365/security/office-365-security/email-authentication-anti-spoofing) 