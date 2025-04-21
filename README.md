# Email Auth Fix para Microsoft 365

Este projeto contém um script Python para análise e correção de problemas de autenticação de email (SPF, DKIM e DMARC) em domínios que utilizam Microsoft 365/Exchange Online.

## Problema

Emails enviados por servidores do Microsoft 365 podem apresentar problemas de autenticação como:

- Falha de SPF: `spf=fail (google.com: domain of user@example.com does not designate 2a01:111:f403:c003::5 as permitted sender)`
- Falha de DMARC: `dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE)`

Estes problemas podem fazer com que os emails sejam marcados como spam ou sejam completamente rejeitados por servidores de destino.

## Funcionalidades

O script oferece as seguintes funcionalidades:

1. **Análise de registros DNS atuais**:
   - Verifica registros SPF
   - Verifica registros DKIM
   - Verifica registros DMARC

2. **Identificação de problemas específicos do Microsoft 365**:
   - Falta de inclusão do domínio `spf.protection.outlook.com` no registro SPF
   - Configuração incorreta ou ausente de seletores DKIM (selector1 e selector2)
   - Políticas DMARC inadequadas

3. **Geração de registros DNS corretos** para cada tipo de autenticação

4. **Comandos para implementação** em diferentes ambientes:
   - BIND9
   - PowerShell
   - Azure CLI

5. **Exportação de relatório em JSON**

## Pré-requisitos

- Python 3.6 ou superior
- Biblioteca dnspython

## Instalação

1. Clone este repositório:
   ```
   git clone https://github.com/seu-usuario/email-auth-fix.git
   cd email-auth-fix
   ```

2. Instale as dependências:
   ```
   pip install -r requirements.txt
   ```

## Uso

### Verificar um domínio

```bash
python email_auth_fix.py exemplo.com.br
```

### Ativar modo detalhado

```bash
python email_auth_fix.py exemplo.com.br -v
```

### Exportar resultados para JSON

```bash
python email_auth_fix.py exemplo.com.br -o resultados.json
```

## Implementando as correções

### 1. Configurando SPF

O registro SPF correto para Microsoft 365 deve incluir:
```
v=spf1 include:spf.protection.outlook.com -all
```

### 2. Configurando DKIM

#### Passo 1: Habilitar DKIM no Centro de Administração do Microsoft 365

1. Acesse o [Centro de administração do Exchange](https://admin.exchange.microsoft.com)
2. Navegue até **Proteção** > **DKIM**
3. Selecione seu domínio e clique em **Habilitar**
4. Anote os registros CNAME que precisam ser adicionados

#### Passo 2: Adicione os registros CNAME ao seu DNS

Você precisará adicionar dois registros CNAME:

```
selector1._domainkey.exemplo.com.br CNAME selector1-exemplo-com-br._domainkey.exemplo.onmicrosoft.com
selector2._domainkey.exemplo.com.br CNAME selector2-exemplo-com-br._domainkey.exemplo.onmicrosoft.com
```

### 3. Configurando DMARC

Um registro DMARC básico recomendado:

```
_dmarc.exemplo.com.br IN TXT "v=DMARC1; p=quarantine; pct=100; rua=mailto:admin@exemplo.com.br; ruf=mailto:admin@exemplo.com.br; fo=1"
```

Onde:
- `p=quarantine`: Indica que emails que falham na autenticação devem ser tratados como spam
- `pct=100`: Aplica a política a 100% dos emails
- `rua`: Endereço para receber relatórios agregados
- `ruf`: Endereço para receber relatórios forenses
- `fo=1`: Solicita relatórios detalhados para qualquer falha de autenticação

## Problemas comuns e soluções

### 1. Erro "SPF não inclui spf.protection.outlook.com"

**Solução**: Adicione o registro SPF correto para Microsoft 365:
```
v=spf1 include:spf.protection.outlook.com -all
```

Se você precisa manter outros serviços no seu registro SPF, combine-os:
```
v=spf1 include:spf.protection.outlook.com include:outro-servico.com -all
```

### 2. Erro "Registro DKIM para seletor 'selector1' não encontrado"

**Solução**: 
1. Habilite DKIM no Centro de Administração do Microsoft 365
2. Adicione os registros CNAME corretos ao seu DNS

### 3. Erro "Política DMARC configurada como 'none'"

**Solução**: Atualize seu registro DMARC para usar uma política mais rigorosa:
```
v=DMARC1; p=quarantine; pct=100; rua=mailto:admin@exemplo.com.br
```

Você pode começar com `p=none` e monitorar os relatórios por algumas semanas antes de mudar para `p=quarantine` ou `p=reject`.

## Nota de transição

Ao implementar as correções, especialmente para DMARC, é recomendável uma abordagem gradual:

1. Comece com `p=none` para monitorar sem impactar a entrega
2. Avance para `p=quarantine` com `pct=10` (aplicando a política a apenas 10% dos emails)
3. Aumente gradualmente o `pct` para 100%
4. Finalmente, considere mudar para `p=reject` quando estiver confiante nos resultados

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para detalhes. # email_auth_fix
