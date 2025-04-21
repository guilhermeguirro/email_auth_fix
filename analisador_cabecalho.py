#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analisador de cabeçalhos de email para identificar problemas de autenticação.
Este script pode analisar um arquivo de cabeçalho de email ou texto colado diretamente.
"""

import argparse
import re
import sys
import json
from datetime import datetime
from typing import Dict, List, Optional, Any


class EmailHeaderAnalyzer:
    """Classe para analisar cabeçalhos de email quanto à autenticação."""

    def __init__(self, verbose: bool = False):
        """
        Inicializa o analisador de cabeçalhos.
        
        Args:
            verbose: Ativa saída detalhada
        """
        self.verbose = verbose
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "authentication": {
                "spf": None,
                "dkim": None,
                "dmarc": None,
                "arc": None
            },
            "headers": {
                "from": None,
                "return_path": None,
                "sender": None,
                "received_spf": None,
                "authentication_results": []
            },
            "issues": [],
            "recommendations": []
        }

    def analyze_header(self, header_text: str) -> Dict[str, Any]:
        """
        Analisa o texto do cabeçalho de email.
        
        Args:
            header_text: Texto do cabeçalho completo
            
        Returns:
            Dicionário com os resultados da análise
        """
        lines = header_text.splitlines()
        
        # Extrair campos relevantes
        self._extract_header_fields(lines)
        
        # Analisar resultados de autenticação
        self._analyze_authentication()
        
        # Gerar recomendações
        self._generate_recommendations()
        
        return self.results
    
    def _extract_header_fields(self, lines: List[str]) -> None:
        """
        Extrai campos importantes dos cabeçalhos.
        
        Args:
            lines: Linhas do cabeçalho
        """
        current_field = None
        current_value = ""
        
        for line in lines:
            if not line.strip():
                continue
                
            # Verificar se é um novo campo ou continuação
            if line[0].isspace():  # Continuação do campo anterior
                if current_field:
                    current_value += " " + line.strip()
            else:  # Novo campo
                # Salvar o campo anterior se existir
                if current_field:
                    self._save_header_field(current_field, current_value)
                
                # Processar o novo campo
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_field = parts[0].lower()
                    current_value = parts[1].strip()
                else:
                    current_field = None
                    current_value = ""
        
        # Salvar o último campo
        if current_field:
            self._save_header_field(current_field, current_value)
    
    def _save_header_field(self, field: str, value: str) -> None:
        """
        Salva o valor de um campo de cabeçalho específico.
        
        Args:
            field: Nome do campo
            value: Valor do campo
        """
        if field == "from":
            self.results["headers"]["from"] = value
        elif field == "return-path":
            self.results["headers"]["return_path"] = value
        elif field == "sender":
            self.results["headers"]["sender"] = value
        elif field == "received-spf":
            self.results["headers"]["received_spf"] = value
        elif field == "authentication-results":
            self.results["headers"]["authentication_results"].append(value)
        elif field == "arc-authentication-results":
            self.results["headers"]["authentication_results"].append(f"ARC: {value}")
    
    def _analyze_authentication(self) -> None:
        """Analisa os resultados de autenticação nos cabeçalhos."""
        # Analisar SPF a partir do campo Received-SPF
        if self.results["headers"]["received_spf"]:
            spf_result = self._extract_spf_from_received_spf()
            self.results["authentication"]["spf"] = spf_result
        
        # Analisar resultados de Authentication-Results
        for auth_result in self.results["headers"]["authentication_results"]:
            self._extract_from_authentication_results(auth_result)
            
        # Verificar problemas
        self._identify_issues()
    
    def _extract_spf_from_received_spf(self) -> Optional[Dict[str, str]]:
        """
        Extrai resultados do SPF do campo Received-SPF.
        
        Returns:
            Dicionário com resultado do SPF ou None
        """
        spf_text = self.results["headers"]["received_spf"]
        
        # Procurar pelo resultado principal (pass, fail, neutral, etc.)
        result_match = re.search(r'^(\w+)', spf_text)
        if not result_match:
            return None
        
        result = result_match.group(1).lower()
        
        # Extrair explicação
        explanation = ""
        reason_match = re.search(r'\((.*?)\)', spf_text)
        if reason_match:
            explanation = reason_match.group(1)
        
        return {
            "result": result,
            "explanation": explanation
        }
    
    def _extract_from_authentication_results(self, auth_result: str) -> None:
        """
        Extrai resultados de autenticação do campo Authentication-Results.
        
        Args:
            auth_result: Texto do campo Authentication-Results
        """
        # Extrair SPF
        spf_match = re.search(r'spf=(\w+)', auth_result)
        if spf_match and not self.results["authentication"]["spf"]:
            result = spf_match.group(1).lower()
            
            explanation = ""
            reason_match = re.search(r'spf=\w+\s+\((.*?)\)', auth_result)
            if reason_match:
                explanation = reason_match.group(1)
            
            self.results["authentication"]["spf"] = {
                "result": result,
                "explanation": explanation
            }
        
        # Extrair DKIM
        dkim_match = re.search(r'dkim=(\w+)', auth_result)
        if dkim_match:
            result = dkim_match.group(1).lower()
            
            explanation = ""
            reason_match = re.search(r'dkim=\w+\s+\((.*?)\)', auth_result)
            if reason_match:
                explanation = reason_match.group(1)
            
            selector = ""
            selector_match = re.search(r'dkim=\w+.*?header\.\w+=(\S+)', auth_result)
            if selector_match:
                selector = selector_match.group(1)
            
            self.results["authentication"]["dkim"] = {
                "result": result,
                "explanation": explanation,
                "selector": selector
            }
        
        # Extrair DMARC
        dmarc_match = re.search(r'dmarc=(\w+)', auth_result)
        if dmarc_match:
            result = dmarc_match.group(1).lower()
            
            explanation = ""
            reason_match = re.search(r'dmarc=\w+\s+\((.*?)\)', auth_result)
            if reason_match:
                explanation = reason_match.group(1)
            
            self.results["authentication"]["dmarc"] = {
                "result": result,
                "explanation": explanation
            }
        
        # Extrair ARC (se disponível)
        arc_match = re.search(r'arc=(\w+)', auth_result)
        if arc_match:
            result = arc_match.group(1).lower()
            
            explanation = ""
            reason_match = re.search(r'arc=\w+\s+\((.*?)\)', auth_result)
            if reason_match:
                explanation = reason_match.group(1)
            
            self.results["authentication"]["arc"] = {
                "result": result,
                "explanation": explanation
            }
    
    def _identify_issues(self) -> None:
        """Identifica problemas de autenticação com base nos resultados."""
        # Verificar problemas de SPF
        if not self.results["authentication"]["spf"]:
            self.results["issues"].append("SPF não encontrado nos cabeçalhos")
        elif self.results["authentication"]["spf"]["result"] != "pass":
            self.results["issues"].append(
                f"Falha de SPF: {self.results['authentication']['spf']['result']} - "
                f"{self.results['authentication']['spf']['explanation']}"
            )
        
        # Verificar problemas de DKIM
        if not self.results["authentication"]["dkim"]:
            self.results["issues"].append("DKIM não encontrado nos cabeçalhos")
        elif self.results["authentication"]["dkim"]["result"] != "pass":
            self.results["issues"].append(
                f"Falha de DKIM: {self.results['authentication']['dkim']['result']} - "
                f"{self.results['authentication']['dkim']['explanation']}"
            )
        
        # Verificar problemas de DMARC
        if not self.results["authentication"]["dmarc"]:
            self.results["issues"].append("DMARC não encontrado nos cabeçalhos")
        elif self.results["authentication"]["dmarc"]["result"] != "pass":
            self.results["issues"].append(
                f"Falha de DMARC: {self.results['authentication']['dmarc']['result']} - "
                f"{self.results['authentication']['dmarc']['explanation']}"
            )
        
        # Verificar problemas de alinhamento
        from_domain = self._extract_domain_from_email(self.results["headers"]["from"])
        return_path_domain = self._extract_domain_from_email(self.results["headers"]["return_path"])
        
        if from_domain and return_path_domain and from_domain != return_path_domain:
            self.results["issues"].append(
                f"Desalinhamento de domínio: From ({from_domain}) ≠ Return-Path ({return_path_domain})"
            )
    
    def _generate_recommendations(self) -> None:
        """Gera recomendações com base nos problemas encontrados."""
        spf_issue = False
        dkim_issue = False
        dmarc_issue = False
        
        for issue in self.results["issues"]:
            if "SPF" in issue:
                spf_issue = True
            if "DKIM" in issue:
                dkim_issue = True
            if "DMARC" in issue:
                dmarc_issue = True
        
        # Domínio principal
        from_domain = self._extract_domain_from_email(self.results["headers"]["from"])
        
        # Recomendações para SPF
        if spf_issue and from_domain:
            self.results["recommendations"].append(
                f"Verifique seu registro SPF para {from_domain} e certifique-se de que "
                f"include:spf.protection.outlook.com está incluído"
            )
            self.results["recommendations"].append(
                f"Registro SPF recomendado: v=spf1 include:spf.protection.outlook.com -all"
            )
        
        # Recomendações para DKIM
        if dkim_issue and from_domain:
            self.results["recommendations"].append(
                f"Verifique se o DKIM está habilitado para {from_domain} no Microsoft 365 "
                f"e se os registros CNAME para selector1._domainkey e selector2._domainkey estão configurados"
            )
        
        # Recomendações para DMARC
        if dmarc_issue and from_domain:
            self.results["recommendations"].append(
                f"Configure um registro DMARC para {from_domain}: "
                f"_dmarc.{from_domain} TXT \"v=DMARC1; p=quarantine; rua=mailto:admin@{from_domain}\""
            )
        
        # Recomendação geral
        if spf_issue or dkim_issue or dmarc_issue:
            self.results["recommendations"].append(
                f"Use o script principal deste projeto para analisar todos os registros DNS: "
                f"python email_auth_fix.py {from_domain} -v"
            )
    
    def _extract_domain_from_email(self, email_header: Optional[str]) -> Optional[str]:
        """
        Extrai o domínio de um campo de cabeçalho de email.
        
        Args:
            email_header: Texto do cabeçalho com endereço de email
            
        Returns:
            Domínio extraído ou None
        """
        if not email_header:
            return None
        
        # Tenta encontrar um endereço de email
        email_match = re.search(r'<?([\w.-]+@([\w.-]+))>?', email_header)
        if email_match:
            return email_match.group(2)
        
        return None
    
    def export_json(self, output_file: str) -> None:
        """
        Exporta os resultados para um arquivo JSON.
        
        Args:
            output_file: Caminho do arquivo de saída
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        
        if self.verbose:
            print(f"Resultados exportados para {output_file}")


def parse_args():
    """Configura e analisa os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description='Analisa cabeçalhos de email para identificar problemas de autenticação.'
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-f', '--file', help='Arquivo com cabeçalhos de email')
    input_group.add_argument('-t', '--text', help='Texto do cabeçalho de email (entre aspas)')
    
    parser.add_argument('-v', '--verbose', action='store_true', help='Exibe informações detalhadas')
    parser.add_argument('-o', '--output', help='Arquivo de saída para exportação JSON')
    
    return parser.parse_args()


def main():
    """Função principal do script."""
    args = parse_args()
    
    try:
        # Obter o texto do cabeçalho
        header_text = ""
        if args.file:
            with open(args.file, 'r', encoding='utf-8') as f:
                header_text = f.read()
        else:
            header_text = args.text
        
        if not header_text.strip():
            print("Erro: O conteúdo do cabeçalho está vazio.", file=sys.stderr)
            return 1
        
        # Analisar o cabeçalho
        analyzer = EmailHeaderAnalyzer(args.verbose)
        results = analyzer.analyze_header(header_text)
        
        # Exibir resumo
        print("\n=== Resumo da Autenticação ===")
        
        # SPF
        if results["authentication"]["spf"]:
            print(f"SPF: {results['authentication']['spf']['result'].upper()}")
            if args.verbose:
                print(f"  Detalhes: {results['authentication']['spf']['explanation']}")
        else:
            print("SPF: Não encontrado")
        
        # DKIM
        if results["authentication"]["dkim"]:
            print(f"DKIM: {results['authentication']['dkim']['result'].upper()}")
            if args.verbose:
                print(f"  Detalhes: {results['authentication']['dkim']['explanation']}")
                if results["authentication"]["dkim"]["selector"]:
                    print(f"  Seletor: {results['authentication']['dkim']['selector']}")
        else:
            print("DKIM: Não encontrado")
        
        # DMARC
        if results["authentication"]["dmarc"]:
            print(f"DMARC: {results['authentication']['dmarc']['result'].upper()}")
            if args.verbose:
                print(f"  Detalhes: {results['authentication']['dmarc']['explanation']}")
        else:
            print("DMARC: Não encontrado")
        
        # ARC
        if results["authentication"]["arc"]:
            print(f"ARC: {results['authentication']['arc']['result'].upper()}")
            if args.verbose:
                print(f"  Detalhes: {results['authentication']['arc']['explanation']}")
        
        # Problemas encontrados
        if results["issues"]:
            print("\n=== Problemas Encontrados ===")
            for issue in results["issues"]:
                print(f"- {issue}")
        else:
            print("\nNenhum problema encontrado! A autenticação está correta.")
        
        # Recomendações
        if results["recommendations"]:
            print("\n=== Recomendações ===")
            for recommendation in results["recommendations"]:
                print(f"- {recommendation}")
        
        # Exportar resultados se solicitado
        if args.output:
            analyzer.export_json(args.output)
            print(f"\nResultados exportados para {args.output}")
        
    except Exception as e:
        print(f"Erro: {str(e)}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 