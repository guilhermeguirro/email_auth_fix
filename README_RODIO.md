# Email Auth Fix - Solução para Microsoft 365
## Desenvolvido especialmente para Ródio Tech Soluções



**Janaína Neto**,

Desenvolvi esta solução completa para resolver os problemas de autenticação de email identificados no domínio **rodio.tec.br**. Abaixo estão os detalhes de implementação e instruções de uso.

## 📋 Problema Identificado

Emails enviados pelo Microsoft 365 da Ródio Tech estão apresentando problemas de autenticação:

```
Falha de SPF: "spf=fail (google.com: domain of janaina.neto@rodio.tec.br does not designate 2a01:111:f403:c003::5 as permitted sender)"
Falha de DMARC: "dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE)"
```

Estas falhas podem fazer com que seus emails sejam classificados como spam ou sejam completamente rejeitados pelos servidores de destino.

## 🛠️ Nossa Solução

O pacote **Email Auth Fix** inclui:

1. **Script Principal** (`email_auth_fix.py`) - Analisa e corrige configurações DNS
2. **Analisador de Cabeçalhos** (`analisador_cabecalho.py`) - Diagnostica problemas em emails enviados
3. **Guias Detalhados** - Instruções passo a passo para Microsoft 365

## 🚀 Como Usar

### 1. Instalação Rápida

```bash
# Clonar o repositório
git clone https://github.com/guiguirro/email-auth-fix.git
cd email-auth-fix

# Instalar dependências
pip install -r requirements.txt
```

### 2. Verificar seu domínio

```bash
python email_auth_fix.py rodio.tec.br -v
```

Este comando irá:
- ✅ Analisar seus registros DNS atuais (SPF, DKIM, DMARC)
- ⚠️ Identificar problemas específicos para Microsoft 365
- 📝 Gerar registros DNS corretos para cada tipo
- 🔧 Fornecer comandos para implementação

### 3. Analisar cabeçalhos de emails problemáticos

```bash
# Analisar a partir de um arquivo
python analisador_cabecalho.py -f cabecalho_email.txt -v

# Ou colar diretamente o cabeçalho
python analisador_cabecalho.py -t "Received: from..."
```

## 📊 Exemplo de Resultados para rodio.tec.br

Após a análise, você receberá recomendações específicas para o seu domínio:

### Registro SPF Recomendado
```
v=spf1 include:spf.protection.outlook.com -all
```

### Registros DKIM Recomendados
```
selector1._domainkey.rodio.tec.br CNAME selector1-rodio-tec-br._domainkey.rodiotech.onmicrosoft.com
selector2._domainkey.rodio.tec.br CNAME selector2-rodio-tec-br._domainkey.rodiotech.onmicrosoft.com
```

### Registro DMARC Recomendado
```
_dmarc.rodio.tec.br IN TXT "v=DMARC1; p=quarantine; pct=100; rua=mailto:admin@rodio.tec.br; ruf=mailto:admin@rodio.tec.br; fo=1"
```

## 📈 Benefícios para a Ródio Tech

1. **Entrega Confiável** - Seus emails chegarão com maior segurança às caixas de entrada
2. **Proteção da Marca** - Evita spoofing e phishing usando seu domínio
3. **Conformidade** - Atende às melhores práticas de segurança de email
4. **Monitoramento** - Receba relatórios sobre tentativas de uso indevido do seu domínio

## 🔒 Implementação na Microsoft 365

O script gera comandos de implementação para diferentes plataformas:

### PowerShell para Microsoft 365
```powershell
Add-DnsServerResourceRecord -ZoneName "rodio.tec.br" -Name "@" -Txt -DescriptiveText "v=spf1 include:spf.protection.outlook.com -all" -TimeToLive 01:00:00

New-DkimSigningConfig -DomainName "rodio.tec.br" -Enabled $true -KeySize 2048 -Selector1 "selector1._domainkey.rodio.tec.br"
New-DkimSigningConfig -DomainName "rodio.tec.br" -Enabled $true -KeySize 2048 -Selector2 "selector2._domainkey.rodio.tec.br"

Add-DnsServerResourceRecord -ZoneName "rodio.tec.br" -Name "_dmarc" -Txt -DescriptiveText "v=DMARC1; p=quarantine; pct=100; rua=mailto:admin@rodio.tec.br; ruf=mailto:admin@rodio.tec.br; fo=1" -TimeToLive 01:00:00
```

## 📖 Recursos Adicionais

Os guias detalhados incluem:
- `guia_m365_dkim.md` - Configuração de DKIM no Microsoft 365
- `guia_spf_dmarc.md` - Melhores práticas para SPF e DMARC

## 📱 Suporte

Estamos à disposição para auxiliar na implementação e tirar dúvidas.

---

*Desenvolvido especialmente para Ródio Tech Soluções*
*© 2023 - Todos os direitos reservados* 
