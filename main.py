# main.py

import base64
import json
import os
import subprocess
from funcoes import cifrar_ficheiro, autenticar_ficheiro, assinar_ficheiro, verificar_assinatura, gerar_chaves_rsa, guardar_se_autenticado


def listar_ficheiros():
    print("\nFicheiros disponíveis:")
    for f in os.listdir('.'):
        if os.path.isfile(f):
            print(f)


def criar_ficheiro(nome):
    with open(nome, 'w') as f:
        f.write('')
    print(f"Ficheiro '{nome}' criado.")


def editar_ficheiro(nome):
    if os.path.exists(nome):
        subprocess.call(['nano', nome])
    else:
        print(f"O ficheiro '{nome}' não existe.")

#mudada a funçao para verificar se o MAC foi autenticado
def ler_ficheiro(nome):
    if os.path.exists(nome):
        print(f"\nConteudo de '{nome}': \n")

        with open(nome, 'r') as f:
            conteudo = f.read()

            if "[MAC]" in conteudo:
                if not os.path.exists("keys-and-iv.txt"):
                    print("Ficheiro autenticado mas 'keys-and-iv.txt' nao encontrado")

                    return
                
                with open("keys-and-iv.txt", 'r') as key_file:
                    keys = json.load(key_file)
                    chave_mac = base64.b64decode(keys["key_mac"])

                valido, mensagem = verificar_mac(nome, chave_mac)
                print(f"verificaçao MAC: {mensagem}")

                if not valido: 
                    return
                
            print(conteudo.split('\n\n[MAC] ')[0])

    else: 
        print(f"o ficheiro '{nome}' nao existe.")


#menu alterado p acomodar funçoes adicionadas (assinatura digital c rsa)
def menu():
    while True:
        print("\n------ Menu ------")
        print("1. Listar ficheiros")
        print("2. Criar ficheiro")
        print("3. Editar ficheiro")
        print("4. Ler ficheiro")
        print("5. Cifrar ficheiro")
        print("6. Autenticar ficheiro")
        print("7. Guardar ficheiro autenticado")
        print("8. Gerar chaves RSA")
        print("9. Assinar ficheiro")
        print("10. Verificar assinatura")
        print("11. Sair")
        print("------------------\n")

        escolha = input("Escolha uma opção: ")

        if escolha == '1':
            listar_ficheiros()
        elif escolha == '2':
            nome = input("Nome do ficheiro: ")
            criar_ficheiro(nome)
        elif escolha == '3':
            nome = input("Nome do ficheiro a editar: ")
            editar_ficheiro(nome)
        elif escolha == '4':
            nome = input("Nome do ficheiro a ler: ")
            ler_ficheiro(nome)
        elif escolha == '5':
            nome = input("Nome do ficheiro a cifrar: ")
            saida = input("Nome do ficheiro de saída (cifrado): ")
            cifrar_ficheiro(nome, saida)
        elif escolha == '6':
            nome = input("Nome do ficheiro a autenticar: ")
            saida = input("Nome do ficheiro de saída (autenticado): ")
            autenticar_ficheiro(nome, saida)
        elif escolha == '7':
            print("Guardar ficheiro apenas se o ficheiro for autenticado.")
            ficheiro_autenticado = input("Nome do ficheiro autenticado: ")    
            ficheiro_saida = input("Nome do ficheiro de saída: ")
            guardar_se_autenticado(ficheiro_autenticado, ficheiro_saida)
        elif escolha == '8':
            gerar_chaves_rsa()
        elif escolha == '9':
            nome = input("Nome do ficheiro a assinar: ")
            assinar_ficheiro(nome)
        elif escolha == '10':
            nome = input("Nome do ficheiro original: ")
            assinatura = input("Nome do ficheiro de assinatura (.sig): ")
            verificar_assinatura(nome, assinatura)
        elif escolha == '11':
            break
        else:
            print("Opção inválida.")


if __name__ == "__main__":
    menu()
