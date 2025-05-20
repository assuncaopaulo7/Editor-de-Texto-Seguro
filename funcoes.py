# funcoes.py

import base64
import json
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def gerar_chaves_e_guardar():
    chave = get_random_bytes(32)       # AES-256
    iv = get_random_bytes(16)          # IV para AES-CBC
    chave_mac = get_random_bytes(32)   # Chave para HMAC-SHA256

    with open("keys-and-iv.txt", "w") as f:
        json.dump({
            "key_cipher": base64.b64encode(chave).decode(),
            "iv": base64.b64encode(iv).decode(),
            "key_mac": base64.b64encode(chave_mac).decode()
        }, f)

    print("Chaves guardadas em 'keys-and-iv.txt'")
    return chave, iv, chave_mac

def cifrar_ficheiro(nome_original, nome_saida):
    try:
        chave, iv, _ = gerar_chaves_e_guardar()

        with open(nome_original, 'r') as f:
            texto = f.read()

        cifra = AES.new(chave, AES.MODE_CBC, iv)
        cifrado = cifra.encrypt(pad(texto.encode(), AES.block_size))
        cifrado_b64 = base64.b64encode(cifrado).decode()

        with open(nome_saida, 'w') as f:
            f.write(cifrado_b64)

        print(f"Ficheiro cifrado guardado como '{nome_saida}'")
        print("Apague o ficheiro 'keys-and-iv.txt' após uso!")
    except Exception as e:
        print(f"Erro ao cifrar ficheiro: {e}")

def autenticar_ficheiro(nome_original, nome_saida):
    try:
        _, _, chave_mac = gerar_chaves_e_guardar()

        with open(nome_original, 'r') as f:
            texto = f.read()

        hmac = HMAC.new(chave_mac, digestmod=SHA256)
        hmac.update(texto.encode())
        mac = hmac.hexdigest()

        with open(nome_saida, 'w') as f:
            f.write(texto + "\n\n[MAC] " + mac)

        print(f"Ficheiro autenticado guardado como '{nome_saida}'")
        print("Apague o ficheiro 'keys-and-iv.txt' após uso!")
    except Exception as e:
        print(f"Erro ao autenticar ficheiro: {e}")

#funçao p autenticar MAC
def verificar_mac(nome_ficheiro, chave_mac):
    try:
        with open(nome_ficheiro, 'r') as f:
            conteudo = f.read().split('\n\n[MAC] ')

            if len(conteudo) != 2:
                return False, "Formato invalido, MAC nao encontrado"

            texto, mac_armazenado = conteudo
            hmac = HMAC.new(chave_mac, digestmod=SHA256)
            hmac.update(texto.encode())
            mac_calculado = hmac.hexdigest()

            if mac_armazenado.strip() ==  mac_calculado:
                return True, "MAC valido, integridade confirmada"
            else:
                return False, "MAC invalido. Ficheiro pode ter sido alterado"

    except Exception as e:
        return False, f"Erro na verificaçao {e}"















