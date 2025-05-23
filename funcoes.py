import os
import json
import base64
import shutil
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def gerar_chaves_rsa():
    key = RSA.generate(2048)
    priv = key.export_key()
    pub = key.publickey().export_key()
    with open("private_key.pem", "wb") as f:
        f.write(priv)
    with open("public_key.pem", "wb") as f:
        f.write(pub)
    print("Chaves RSA geradas: private_key.pem, public_key.pem")
    return priv, pub

def assinar_ficheiro(nome_ficheiro, private_key_path="private_key.pem"):
    try:
        with open(private_key_path, "rb") as f:
            priv = RSA.import_key(f.read())
        with open(nome_ficheiro, "rb") as f:
            data = f.read()
        h = SHA256.new(data)
        sig = pkcs1_15.new(priv).sign(h)
        path = nome_ficheiro + ".sig"
        with open(path, "wb") as f:
            f.write(sig)
        print(f"Assinatura guardada em '{path}'")
        return sig
    except Exception as e:
        print("Erro ao assinar:", e)
        return None

def verificar_assinatura(nome_ficheiro, signature_path, public_key_path="public_key.pem"):
    try:
        with open(public_key_path, "rb") as f:
            pub = RSA.import_key(f.read())
        with open(nome_ficheiro, "rb") as f:
            data = f.read()
        with open(signature_path, "rb") as f:
            sig = f.read()
        h = SHA256.new(data)
        pkcs1_15.new(pub).verify(h, sig)
        print("Assinatura válida.")
        return True
    except (ValueError, TypeError) as e:
        print("Assinatura inválida:", e)
        return False
    except Exception as e:
        print("Erro na verificação:", e)
        return False

def gerar_chaves_por_ficheiro(nome_saida):
    chave = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)     # IV CBC
    chave_mac = get_random_bytes(32)  # HMAC-SHA256

    key_data = {
        "key_cipher": base64.b64encode(chave).decode(),
        "iv": base64.b64encode(iv).decode(),
        "key_mac": base64.b64encode(chave_mac).decode()
    }
    key_file = f"{nome_saida}.key.txt"
    with open(key_file, "w") as f:
        json.dump(key_data, f, indent=4)
    print(f"Chaves guardadas em '{key_file}' — apague-o após uso!")
    return chave, iv, chave_mac

def ler_chaves_de_ficheiro(key_file):
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"Ficheiro de chaves '{key_file}' não encontrado.")
    with open(key_file, "r") as f:
        data = json.load(f)
    try:
        chave = base64.b64decode(data["key_cipher"])
        iv = base64.b64decode(data["iv"])
        chave_mac = base64.b64decode(data["key_mac"])
    except KeyError as e:
        raise KeyError(f"Campo de chave em falta no ficheiro: {e}")
    return chave, iv, chave_mac

def cifrar_ficheiro(nome_original, nome_saida):
    try:
        chave, iv, _ = gerar_chaves_por_ficheiro(nome_saida)
        with open(nome_original, "rb") as f:
            pt = f.read()
        cipher = AES.new(chave, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(pt, AES.block_size))
        with open(nome_saida, "wb") as f:
            f.write(ct)
        print(f"'{nome_saida}' cifrado com sucesso. Chaves em '{nome_saida}.key.txt' — apague-as após uso!")
    except Exception as e:
        print("Erro ao cifrar:", e)

def decifrar_ficheiro(nome_cifrado, nome_saida):
    try:
        key_file = f"{nome_cifrado}.key.txt"
        chave, iv, _ = ler_chaves_de_ficheiro(key_file)
        with open(nome_cifrado, "rb") as f:
            ct = f.read()
        cipher = AES.new(chave, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        with open(nome_saida, "wb") as f:
            f.write(pt)
        print(f"'{nome_saida}' decifrado com sucesso.")
    except Exception as e:
        print("Erro ao decifrar:", e)

def autenticar_ficheiro(nome_original, nome_saida):
    try:
        _, _, chave_mac = gerar_chaves_por_ficheiro(nome_saida + ".auth")
        with open(nome_original, "rb") as f:
            data = f.read()
        h = HMAC.new(chave_mac, digestmod=SHA256)
        h.update(data)
        mac = h.hexdigest()
        with open(nome_saida, "w") as f:
            f.write(data.decode(errors="ignore") + "\n\n[MAC] " + mac)
        print(f"'{nome_saida}' autenticado com sucesso. Chave MAC em '{nome_saida}.auth.key.txt'.")
    except Exception as e:
        print("Erro ao autenticar:", e)

def verificar_mac(nome_ficheiro, auth_key_file):
    try:
        _, _, chave_mac = ler_chaves_de_ficheiro(auth_key_file)
        txt, mac_stored = open(nome_ficheiro, "r").read().split("\n\n[MAC] ")
    except Exception as e:
        print("Erro na verificação de MAC:", e)
        return False
    h = HMAC.new(chave_mac, digestmod=SHA256)
    h.update(txt.encode())
    if h.hexdigest() == mac_stored.strip():
        print("MAC válido.")
        return True
    else:
        print("MAC inválido.")
        return False

def guardar_se_autenticado(nome_entrada, nome_saida, auth_key_file):
    if verificar_mac(nome_entrada, auth_key_file):
        try:
            shutil.copyfile(nome_entrada, nome_saida)
            print("Ficheiro guardado com sucesso.")
        except Exception as e:
            print(f"Erro ao guardar ficheiro: {e}")
    else:
        print("Ficheiro NÃO autenticado. Guardar não é permitido.")