#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Verificação rápida de autenticação de email para Ródio Tech Soluções.
Este script simplificado verifica especificamente o domínio rodio.tec.br.
"""

import sys
import os
import subprocess
import webbrowser

def banner():
    print("""
╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭╮
┃╭━╮┃╱╱╱╱╱╱╱╱╱╱╱╱┃╭━╮┃╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱┃┃
┃╰━╯┣━━┣━━┳╮╭┳━━╮┃╰━━┳━━┳━━┳╮╭┃╭━━┳━━┳━━┫┃
┃╭╮╭┫╭╮┃╭╮┃╰╯┃┃━┫╰━━╮┃╭╮┃┃━┫╰╯┃┃╭━┫╭╮┃━━┫┃
┃┃┃╰┫╰╯┃╰╯┃┃┃┃┃━┫┃╰━╯┃╭╮┃┃━┫┃┃┃┃╰━┫╭╮┣━━┃╰╮
╰╯╰━┻━━┻━━┻┻┻┻━━╯╰━━━┻╯╰┻━━┻┻┻╯╰━━┻╯╰┻━━┻━╯
    """)
    print("VERIFICAÇÃO RÁPIDA DE EMAIL - RÓDIO TECH SOLUÇÕES")
    print("-----------------------------------------------\n")

def check_requirements():
    """Verifica se as dependências estão instaladas."""
    try:
        import dns.resolver
        return True
    except ImportError:
        print("Instalando dependência necessária (dnspython)...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "dnspython"])
            return True
        except Exception as e:
            print(f"Erro ao instalar dependência: {e}")
            return False

def verify_rodio_domain():
    """Verifica especificamente o domínio rodio.tec.br."""
    domain = "rodio.tec.br"
    
    print(f"\nVerificando configuração de email para {domain}...\n")
    
    # Executar o script principal com o domínio da Ródio
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "email_auth_fix.py")
    
    if not os.path.exists(script_path):
        print(f"Erro: Script principal não encontrado em {script_path}")
        print("Por favor, execute este script do diretório do projeto.")
        return False
    
    try:
        result = subprocess.run(
            [sys.executable, script_path, domain, "-v"],
            capture_output=True,
            text=True
        )
        
        # Exibir resultados
        print(result.stdout)
        
        # Verificar se houve algum erro
        if result.returncode != 0:
            print("Erro durante a verificação:")
            print(result.stderr)
            return False
        
        return True
    
    except Exception as e:
        print(f"Erro ao executar a verificação: {e}")
        return False

def show_options():
    """Mostra as opções disponíveis."""
    print("\nO que você gostaria de fazer agora?")
    print("1. Abrir guia de configuração do DKIM no Microsoft 365")
    print("2. Abrir guia de configuração do SPF/DMARC")
    print("3. Ver exemplo de diagnóstico para rodio.tec.br")
    print("4. Sair")
    
    choice = input("\nEscolha uma opção (1-4): ")
    
    if choice == "1":
        dkim_guide = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guia_m365_dkim.md")
        if os.path.exists(dkim_guide):
            try:
                with open(dkim_guide, 'r', encoding='utf-8') as f:
                    print("\n" + "="*70)
                    print(f.read())
                    print("="*70)
            except Exception:
                webbrowser.open(dkim_guide)
        else:
            print("Guia não encontrado. Abrindo documentação online...")
            webbrowser.open("https://learn.microsoft.com/pt-br/microsoft-365/security/office-365-security/email-authentication-dkim-configure")
    
    elif choice == "2":
        spf_guide = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guia_spf_dmarc.md")
        if os.path.exists(spf_guide):
            try:
                with open(spf_guide, 'r', encoding='utf-8') as f:
                    print("\n" + "="*70)
                    print(f.read())
                    print("="*70)
            except Exception:
                webbrowser.open(spf_guide)
        else:
            print("Guia não encontrado. Abrindo documentação online...")
            webbrowser.open("https://learn.microsoft.com/pt-br/microsoft-365/security/office-365-security/email-authentication-spf-configure")
    
    elif choice == "3":
        exemplo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exemplo_rodio.md")
        if os.path.exists(exemplo):
            try:
                with open(exemplo, 'r', encoding='utf-8') as f:
                    print("\n" + "="*70)
                    print(f.read())
                    print("="*70)
            except Exception:
                webbrowser.open(exemplo)
        else:
            print("Exemplo não encontrado.")
    
    elif choice == "4":
        print("\nObrigado por usar a verificação rápida da Ródio Tech!")
        return False
    
    return True

def main():
    """Função principal."""
    banner()
    
    if not check_requirements():
        print("Não foi possível configurar o ambiente necessário.")
        print("Por favor, instale manualmente a biblioteca 'dnspython'.")
        return 1
    
    if not verify_rodio_domain():
        print("\nA verificação encontrou problemas. Por favor, verifique os detalhes acima.")
    else:
        print("\nVerificação concluída com sucesso!")
    
    # Loop de opções
    while show_options():
        pass
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 