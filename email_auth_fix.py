#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para análise e correção de problemas de autenticação de email (SPF, DKIM, DMARC)
para domínios que utilizam Microsoft 365/Exchange Online.
"""

import argparse
import json
import re
import sys
import dns.resolver
import dns.exception
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any


class EmailAuthChecker:
    """Classe principal para verificação e correção de problemas de autenticação de email."""

    def __init__(self, domain: str, verbose: bool = False):
        """
        Inicializa o verificador de autenticação de email.

        Args:
            domain: Domínio a ser verificado
            verbose: Ativa saída detalhada
        """
        self.domain = domain
        self.verbose = verbose
        self.results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "records": {
                "spf": None,
                "dkim": None,
                "dmarc": None
            },
            "issues": [],
            "recommendations": {
                "spf": None,
                "dkim": None,
                "dmarc": None
            },
            "commands": {
                "bind9": [],
                "powershell": [],
                "azure_cli": []
            }
        }

    def check_all(self) -> Dict[str, Any]:
        """Executa todas as verificações de autenticação de email."""
        self._print_verbose(f"Verificando domínio: {self.domain}")
        
        self.check_spf()
        self.check_dkim()
        self.check_dmarc()
        
        self._generate_commands()
        
        return self.results

    def check_spf(self) -> None:
        """Verifica e analisa o registro SPF."""
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            spf_records = [str(rdata).strip('"') for rdata in answers if str(rdata).startswith('"v=spf1')]
            
            if not spf_records:
                self.results["issues"].append("Registro SPF não encontrado")
                self.results["records"]["spf"] = None
                self._recommend_spf_record()
                return
            
            if len(spf_records) > 1:
                self.results["issues"].append("Múltiplos registros SPF encontrados (apenas um é permitido)")
            
            spf_record = spf_records[0]
            self.results["records"]["spf"] = spf_record
            
            if "include:spf.protection.outlook.com" not in spf_record:
                self.results["issues"].append("Registro SPF não inclui spf.protection.outlook.com")
            
            if "~all" not in spf_record and "-all" not in spf_record:
                self.results["issues"].append("Registro SPF não possui mecanismo de proteção 'all' adequado")
            
            self._recommend_spf_record()
            
        except dns.exception.DNSException as e:
            self.results["issues"].append(f"Erro ao consultar registro SPF: {str(e)}")
            self._recommend_spf_record()

    def check_dkim(self) -> None:
        """Verifica e analisa os registros DKIM para Microsoft 365."""
        selectors = ["selector1", "selector2"]
        found_selectors = []
        
        for selector in selectors:
            dkim_name = f"{selector}._domainkey.{self.domain}"
            try:
                answers = dns.resolver.resolve(dkim_name, 'CNAME')
                found_selectors.append({
                    "selector": selector,
                    "record": str(answers[0]),
                    "type": "CNAME"
                })
            except dns.exception.DNSException:
                try:
                    answers = dns.resolver.resolve(dkim_name, 'TXT')
                    found_selectors.append({
                        "selector": selector,
                        "record": str(answers[0]).strip('"'),
                        "type": "TXT"
                    })
                except dns.exception.DNSException:
                    self.results["issues"].append(f"Registro DKIM para seletor '{selector}' não encontrado")
        
        self.results["records"]["dkim"] = found_selectors
        
        if not found_selectors:
            self.results["issues"].append("Nenhum registro DKIM para Microsoft 365 encontrado")
        elif len(found_selectors) < 2:
            self.results["issues"].append("Microsoft 365 requer dois registros DKIM (selector1 e selector2)")
        
        self._recommend_dkim_records()

    def check_dmarc(self) -> None:
        """Verifica e analisa o registro DMARC."""
        dmarc_name = f"_dmarc.{self.domain}"
        
        try:
            answers = dns.resolver.resolve(dmarc_name, 'TXT')
            dmarc_records = [str(rdata).strip('"') for rdata in answers if str(rdata).startswith('"v=DMARC1')]
            
            if not dmarc_records:
                self.results["issues"].append("Registro DMARC não encontrado")
                self.results["records"]["dmarc"] = None
                self._recommend_dmarc_record()
                return
            
            dmarc_record = dmarc_records[0]
            self.results["records"]["dmarc"] = dmarc_record
            
            # Analisar parâmetros DMARC
            p_match = re.search(r'p=(\w+)', dmarc_record)
            p_value = p_match.group(1) if p_match else None
            
            if not p_value:
                self.results["issues"].append("Política DMARC (p=) não especificada")
            elif p_value == "none":
                self.results["issues"].append("Política DMARC configurada como 'none' (monitoramento apenas)")
            
            rua_match = re.search(r'rua=mailto:([^\s;]+)', dmarc_record)
            if not rua_match:
                self.results["issues"].append("Relatórios de DMARC (rua=) não configurados")
            
            pct_match = re.search(r'pct=(\d+)', dmarc_record)
            pct_value = int(pct_match.group(1)) if pct_match else 100
            
            if pct_value < 100:
                self.results["issues"].append(f"Porcentagem DMARC (pct={pct_value}) menor que 100% - aplicação parcial")
            
            self._recommend_dmarc_record()
            
        except dns.exception.DNSException as e:
            self.results["issues"].append(f"Erro ao consultar registro DMARC: {str(e)}")
            self._recommend_dmarc_record()

    def _recommend_spf_record(self) -> None:
        """Gera uma recomendação para o registro SPF correto."""
        recommended_spf = f'v=spf1 include:spf.protection.outlook.com -all'
        self.results["recommendations"]["spf"] = recommended_spf

    def _recommend_dkim_records(self) -> None:
        """Gera recomendações para os registros DKIM do Microsoft 365."""
        tenant_domain = self._extract_tenant_domain()
        
        if not tenant_domain:
            tenant_domain = "tenant.onmicrosoft.com"
            self.results["issues"].append("Não foi possível determinar o domínio do tenant do Microsoft 365. Substitua 'tenant.onmicrosoft.com' pelo seu domínio real.")
        
        dkim_recommendations = []
        for selector in ["selector1", "selector2"]:
            dkim_recommendations.append({
                "selector": selector,
                "host": f"{selector}._domainkey.{self.domain}",
                "value": f"{selector}-{self.domain.replace('.', '-')}._domainkey.{tenant_domain}",
                "type": "CNAME"
            })
        
        self.results["recommendations"]["dkim"] = dkim_recommendations

    def _recommend_dmarc_record(self) -> None:
        """Gera uma recomendação para o registro DMARC correto."""
        admin_email = f"admin@{self.domain}"
        recommended_dmarc = f'v=DMARC1; p=quarantine; pct=100; rua=mailto:{admin_email}; ruf=mailto:{admin_email}; fo=1'
        self.results["recommendations"]["dmarc"] = recommended_dmarc

    def _extract_tenant_domain(self) -> Optional[str]:
        """Tenta extrair o domínio do tenant do Microsoft 365 dos registros existentes."""
        if self.results["records"]["dkim"]:
            for selector_info in self.results["records"]["dkim"]:
                if selector_info["type"] == "CNAME":
                    cname_value = selector_info["record"]
                    match = re.search(r'_domainkey\.([^.]+\.onmicrosoft\.com)\.?$', cname_value)
                    if match:
                        return match.group(1)
        return None

    def _generate_commands(self) -> None:
        """Gera comandos para diferentes plataformas."""
        # Comandos BIND9
        if self.results["recommendations"]["spf"]:
            spf_cmd = f'{self.domain}. IN TXT "{self.results["recommendations"]["spf"]}"'
            self.results["commands"]["bind9"].append(spf_cmd)
        
        if self.results["recommendations"]["dkim"]:
            for dkim_rec in self.results["recommendations"]["dkim"]:
                dkim_cmd = f'{dkim_rec["host"]}. IN CNAME {dkim_rec["value"]}.'
                self.results["commands"]["bind9"].append(dkim_cmd)
        
        if self.results["recommendations"]["dmarc"]:
            dmarc_cmd = f'_dmarc.{self.domain}. IN TXT "{self.results["recommendations"]["dmarc"]}"'
            self.results["commands"]["bind9"].append(dmarc_cmd)
        
        # Comandos PowerShell para Office 365
        if self.results["recommendations"]["spf"]:
            ps_spf = f'Add-DnsServerResourceRecord -ZoneName "{self.domain}" -Name "@" -Txt -DescriptiveText "{self.results["recommendations"]["spf"]}" -TimeToLive 01:00:00'
            self.results["commands"]["powershell"].append(ps_spf)
        
        if self.results["recommendations"]["dkim"]:
            for dkim_rec in self.results["recommendations"]["dkim"]:
                selector = dkim_rec["selector"].replace("selector", "")
                ps_dkim = f'New-DkimSigningConfig -DomainName "{self.domain}" -Enabled $true -KeySize 2048 -Selector{selector} "{dkim_rec["host"]}"'
                self.results["commands"]["powershell"].append(ps_dkim)
        
        if self.results["recommendations"]["dmarc"]:
            ps_dmarc = f'Add-DnsServerResourceRecord -ZoneName "{self.domain}" -Name "_dmarc" -Txt -DescriptiveText "{self.results["recommendations"]["dmarc"]}" -TimeToLive 01:00:00'
            self.results["commands"]["powershell"].append(ps_dmarc)
        
        # Comandos Azure CLI
        if self.results["recommendations"]["spf"]:
            az_spf = f'az network dns record-set txt add-record -g YourResourceGroup -z {self.domain} -n "@" -v "{self.results["recommendations"]["spf"]}"'
            self.results["commands"]["azure_cli"].append(az_spf)
        
        if self.results["recommendations"]["dkim"]:
            for dkim_rec in self.results["recommendations"]["dkim"]:
                selector = dkim_rec["selector"]
                az_dkim = f'az network dns record-set cname set-record -g YourResourceGroup -z {self.domain} -n "{selector}._domainkey" -c "{dkim_rec["value"]}"'
                self.results["commands"]["azure_cli"].append(az_dkim)
        
        if self.results["recommendations"]["dmarc"]:
            az_dmarc = f'az network dns record-set txt add-record -g YourResourceGroup -z {self.domain} -n "_dmarc" -v "{self.results["recommendations"]["dmarc"]}"'
            self.results["commands"]["azure_cli"].append(az_dmarc)

    def export_json(self, output_file: str) -> None:
        """
        Exporta os resultados para um arquivo JSON.
        
        Args:
            output_file: Caminho do arquivo de saída
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        self._print_verbose(f"Resultados exportados para {output_file}")

    def _print_verbose(self, message: str) -> None:
        """Imprime mensagem se o modo verbose estiver ativado."""
        if self.verbose:
            print(message)


def parse_args():
    """Configura e analisa os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description='Verifica e corrige problemas de autenticação de email (SPF, DKIM, DMARC) para Microsoft 365.'
    )
    parser.add_argument('domain', help='Domínio a ser verificado')
    parser.add_argument('-v', '--verbose', action='store_true', help='Exibe informações detalhadas')
    parser.add_argument('-o', '--output', help='Arquivo de saída para exportação JSON')
    return parser.parse_args()


def main():
    """Função principal do script."""
    args = parse_args()
    
    try:
        checker = EmailAuthChecker(args.domain, args.verbose)
        results = checker.check_all()
        
        # Exibir resultados
        if results["issues"]:
            print(f"\nProblemas encontrados ({len(results['issues'])}):")
            for issue in results["issues"]:
                print(f"- {issue}")
        else:
            print("\nNenhum problema encontrado!")
        
        print("\nRegistros atuais:")
        if results["records"]["spf"]:
            print(f"SPF: {results['records']['spf']}")
        else:
            print("SPF: Não encontrado")
        
        if results["records"]["dkim"]:
            print("DKIM:")
            for dkim in results["records"]["dkim"]:
                print(f"  - {dkim['selector']}: {dkim['record']}")
        else:
            print("DKIM: Não encontrado")
        
        if results["records"]["dmarc"]:
            print(f"DMARC: {results['records']['dmarc']}")
        else:
            print("DMARC: Não encontrado")
        
        print("\nRecomendações:")
        if results["recommendations"]["spf"]:
            print(f"SPF: {results['recommendations']['spf']}")
        
        if results["recommendations"]["dkim"]:
            print("DKIM:")
            for dkim in results["recommendations"]["dkim"]:
                print(f"  - {dkim['selector']}: {dkim['host']} CNAME {dkim['value']}")
        
        if results["recommendations"]["dmarc"]:
            print(f"DMARC: {results['recommendations']['dmarc']}")
        
        # Exportar resultados se solicitado
        if args.output:
            checker.export_json(args.output)
            print(f"\nResultados exportados para {args.output}")
        
    except Exception as e:
        print(f"Erro: {str(e)}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 