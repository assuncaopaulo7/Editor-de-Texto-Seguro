# main.py

import os
import subprocess
from funcoes import cifrar_ficheiro, autenticar_ficheiro


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


def ler_ficheiro(nome):
    if os.path.exists(nome):
        print(f"\nConteúdo de '{nome}':\n")
        with open(nome, 'r') as f:
            conteudo = f.read()
            print(conteudo)
    else:
        print(f"O ficheiro '{nome}' não existe.")


def menu():
    while True:
        print("\n------ Menu ------")
        print("1. Listar ficheiros")
        print("2. Criar ficheiro")
        print("3. Editar ficheiro")
        print("4. Ler ficheiro")
        print("5. Cifrar ficheiro")
        print("6. Autenticar ficheiro")
        print("7. Sair")
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
            break
        else:
            print("Opção inválida.")


if __name__ == "__main__":
    menu()
