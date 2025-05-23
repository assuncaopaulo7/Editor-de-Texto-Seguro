import os
import json
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
import funcoes

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR   = os.path.join(SCRIPT_DIR, "ficheiros")

os.makedirs(BASE_DIR, exist_ok=True)
os.chdir(BASE_DIR)

class SecureEditorApp:
    def __init__(self, root):
        self.root = root
        root.title("Editor de Texto Seguro")
        root.resizable(False, False)
        self.build_ui()

    def ask_yes_no_pt(self, title, message):
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.resizable(False, False)
        tk.Label(dlg, text=message, wraplength=300, padx=20, pady=10).pack()
        result = {'value': False}
        def on_sim(): result['value'] = True; dlg.destroy()
        def on_nao(): result['value'] = False; dlg.destroy()
        frame = tk.Frame(dlg, pady=10)
        frame.pack()
        tk.Button(frame, text="Sim", width=10, command=on_sim).pack(side='left', padx=5)
        tk.Button(frame, text="Não", width=10, command=on_nao).pack(side='left', padx=5)
        dlg.transient(self.root)
        dlg.grab_set()
        self.root.wait_window(dlg)
        return result['value']

    def build_ui(self):
        frame = tk.Frame(self.root, padx=10, pady=10)
        frame.pack()
        buttons = [
            ("Criar/Editar Ficheiro", self.create_or_edit),
            ("Abrir Ficheiro",        self.open_file),
            ("Cifrar Ficheiro",       self.encrypt_file),
            ("Decifrar Ficheiro",     self.decrypt_file),
            ("Autenticar Ficheiro",   self.authenticate_file),
            ("Guardar Autenticado",   self.save_authenticated),
            ("Gerir Chaves",          self.manage_keys),
            ("Gerar Chaves RSA",      funcoes.gerar_chaves_rsa),
            ("Assinar Ficheiro",      self.sign_file),
            ("Verificar Assinatura",  self.verify_signature),
            ("Eliminar Ficheiro",     self.delete_file),
            ("Sair",                  self.root.quit)
        ]
        for (txt, cmd) in buttons:
            tk.Button(frame, text=txt, width=25, command=cmd).pack(pady=2)

    def manage_keys(self):
        files = filedialog.askopenfilenames(
            title="Selecione ficheiros de chave para eliminar",
            initialdir=BASE_DIR,
            filetypes=[("Ficheiros de chave","*.key.txt"), ("Todos","*.*")]
        )
        if not files:
            return
        for key_file in files:
            nome = os.path.basename(key_file)
            apagar = self.ask_yes_no_pt(
                "Eliminar Chave",
                f"Deseja eliminar o ficheiro de chaves '{nome}'?"
            )
            if apagar:
                try:
                    os.remove(key_file)
                    messagebox.showinfo("Remoção", f"Ficheiro '{nome}' apagado com sucesso.")
                except Exception as e:
                    messagebox.showerror("Erro", f"Não foi possível apagar '{nome}': {e}")

    def create_or_edit(self):
        path = filedialog.asksaveasfilename(
            initialdir=BASE_DIR, defaultextension=".txt",
            filetypes=[("Ficheiros de texto","*.txt")],
            title="Criar ou editar ficheiro"
        )
        if not path:
            return
        path = os.path.join(BASE_DIR, os.path.basename(path))

        content = ""
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

        win = tk.Toplevel(self.root)
        win.title(f"Editar: {os.path.basename(path)}")
        win.resizable(False, False)
        text_widget = tk.Text(win, wrap='word', width=80, height=25)
        text_widget.pack(expand=True, fill='both')
        text_widget.insert("1.0", content)

        def ask_remove_key(key_file):
            if os.path.exists(key_file):
                apagar = self.ask_yes_no_pt(
                    "Chave de Ficheiro",
                    f"Deseja apagar o ficheiro de chaves '{os.path.basename(key_file)}'?"
                )
                if apagar:
                    try:
                        os.remove(key_file)
                        messagebox.showinfo("Remoção", f"Ficheiro '{os.path.basename(key_file)}' apagado.")
                    except Exception as e:
                        messagebox.showerror("Erro", f"Não foi possível apagar '{os.path.basename(key_file)}': {e}")

        def on_save():
            novo = text_widget.get("1.0", "end-1c")
            modo = self.ask_mode()
            if not modo:
                messagebox.showerror("Erro","Proteção não selecionada")
                return

            if modo == "cifrar":
                dest = filedialog.asksaveasfilename(
                    initialdir=BASE_DIR, defaultextension=".aes",
                    filetypes=[("Ficheiros AES","*.aes")],
                    title="Guardar cifrado como"
                )
                if dest:
                    chave, iv, _ = funcoes.gerar_chaves_por_ficheiro(dest)
                    ct = AES.new(chave, AES.MODE_CBC, iv).encrypt(pad(novo.encode(), AES.block_size))
                    with open(dest, "wb") as f:
                        f.write(ct)
                    key_file = f"{dest}.key.txt"
                    messagebox.showinfo(
                        "Sucesso",
                        f"Ficheiro cifrado: {os.path.basename(dest)}\nChaves: '{os.path.basename(key_file)}'"
                    )
                    ask_remove_key(key_file)

            elif modo == "autenticar":
                dest = filedialog.asksaveasfilename(
                    initialdir=BASE_DIR, defaultextension=".mac",
                    filetypes=[("Ficheiros MAC","*.mac")],
                    title="Guardar autenticado como"
                )
                if dest:
                    _, _, chave_mac = funcoes.gerar_chaves_por_ficheiro(dest)
                    h = HMAC.new(chave_mac, digestmod=SHA256)
                    h.update(novo.encode())
                    mac = h.hexdigest()
                    with open(dest, "w", encoding="utf-8") as f:
                        f.write(novo + "\n\n[MAC] " + mac)
                    key_file = f"{dest}.key.txt"
                    messagebox.showinfo(
                        "Sucesso",
                        f"MAC gerado: {os.path.basename(dest)}\nChaves: '{os.path.basename(key_file)}'"
                    )
                    ask_remove_key(key_file)

            else:
                d1 = filedialog.asksaveasfilename(
                    initialdir=BASE_DIR, defaultextension=".aes",
                    filetypes=[("Ficheiros AES","*.aes")],
                    title="Guardar cifrado como"
                )
                if not d1:
                    return
                d2 = filedialog.asksaveasfilename(
                    initialdir=BASE_DIR, defaultextension=".mac",
                    filetypes=[("Ficheiros MAC","*.mac")],
                    title="Guardar MAC como"
                )
                if not d2:
                    return

                chave, iv, chave_mac = funcoes.gerar_chaves_por_ficheiro(d1)
                ct = AES.new(chave, AES.MODE_CBC, iv).encrypt(pad(novo.encode(), AES.block_size))
                with open(d1, "wb") as f:
                    f.write(ct)

                h = HMAC.new(chave_mac, digestmod=SHA256)
                h.update(ct)
                mac = h.hexdigest()
                with open(d2, "w", encoding="utf-8") as f:
                    f.write(mac)

                key_file = f"{d1}.key.txt"
                messagebox.showinfo(
                    "Sucesso",
                    f"Cifrado: {os.path.basename(d1)}\nMAC: {os.path.basename(d2)}\nChaves: '{os.path.basename(key_file)}'"
                )
                ask_remove_key(key_file)

            win.destroy()

        tk.Button(win, text="Guardar", width=10, command=on_save).pack(pady=10)

    def ask_mode(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Proteção")
        dlg.resizable(False, False)
        tk.Label(dlg, text="Escolha o modo de proteção:", pady=10).pack()
        var = tk.StringVar()
        frame = tk.Frame(dlg)
        frame.pack(pady=5)
        def sel(m): var.set(m); dlg.destroy()
        tk.Button(frame, text="Cifrar", width=12, command=lambda: sel("cifrar")).pack(side='left', padx=5)
        tk.Button(frame, text="Autenticar", width=12, command=lambda: sel("autenticar")).pack(side='left', padx=5)
        tk.Button(frame, text="Ambas", width=12, command=lambda: sel("ambas")).pack(side='left', padx=5)
        dlg.transient(self.root)
        dlg.grab_set()
        self.root.wait_window(dlg)
        return var.get()

    def open_file(self):
        f = filedialog.askopenfilename(
            initialdir=BASE_DIR,
            title="Abrir ficheiro",
            filetypes=[("Todos","*.*")]
        )
        if not f:
            return
        data = open(f, "rb").read()
        txt = None
        key_file = None

        def ask_remove_key(key_file):
            if os.path.exists(key_file):
                apagar = self.ask_yes_no_pt(
                    "Chave de Ficheiro",
                    f"Deseja apagar o ficheiro de chaves '{os.path.basename(key_file)}'?"
                )
                if apagar:
                    try:
                        os.remove(key_file)
                        messagebox.showinfo("Remoção", f"Ficheiro '{os.path.basename(key_file)}' apagado.")
                    except Exception as e:
                        messagebox.showerror("Erro", f"Não foi possível apagar '{os.path.basename(key_file)}': {e}")

        if f.lower().endswith(".aes"):
            k = filedialog.askopenfilename(
                title="Abrir chave (.key.txt)",
                initialdir=BASE_DIR,
                filetypes=[("Ficheiros de chave","*.key.txt")]
            )
            if not k:
                return
            key_file = k
            chave, iv, _ = funcoes.ler_chaves_de_ficheiro(k)
            try:
                txt = unpad(AES.new(chave, AES.MODE_CBC, iv).decrypt(data), AES.block_size).decode()
            except Exception:
                messagebox.showerror("Erro", "Decifrar falhou")
                return

        elif f.lower().endswith(".mac"):
            k = filedialog.askopenfilename(
                title="Abrir chave MAC (.key.txt)",
                initialdir=BASE_DIR,
                filetypes=[("Ficheiros de chave","*.key.txt")]
            )
            if not k:
                return
            key_file = k
            _, _, chave_mac = funcoes.ler_chaves_de_ficheiro(k)
            ok = funcoes.verificar_mac(f, k)
            if not ok:
                messagebox.showerror("MAC inválido", "Verificação falhou")
                return
            txt = open(f, "r", encoding="utf-8").read().split("\n\n[MAC] ")[0]
        else:
            txt = data.decode(errors="ignore")

        vw = tk.Toplevel(self.root)
        vw.title(f"Ver: {os.path.basename(f)}")
        vw.resizable(False, False)
        t = tk.Text(vw, wrap='word', width=80, height=25)
        t.pack(expand=True, fill='both')
        t.insert("1.0", txt)

        if key_file:
            ask_remove_key(key_file)

    def encrypt_file(self):
        src = filedialog.askopenfilename(
            initialdir=BASE_DIR,
            title="Abrir ficheiro para cifrar"
        )
        if not src:
            return
        dst = filedialog.asksaveasfilename(
            initialdir=BASE_DIR,
            defaultextension=".aes",
            filetypes=[("Ficheiros AES","*.aes")],
            title="Guardar cifrado como"
        )
        if dst:
            funcoes.cifrar_ficheiro(src, dst)

    def decrypt_file(self):
        src = filedialog.askopenfilename(
            initialdir=BASE_DIR,
            title="Abrir ficheiro cifrado",
            filetypes=[("Ficheiros AES","*.aes")]
        )
        if not src:
            return
        dst = filedialog.asksaveasfilename(
            initialdir=BASE_DIR,
            defaultextension=".txt",
            filetypes=[("Ficheiros de texto","*.txt")],
            title="Guardar decifrado como"
        )
        if dst:
            funcoes.decifrar_ficheiro(src, dst)

    def authenticate_file(self):
        src = filedialog.askopenfilename(
            initialdir=BASE_DIR,
            title="Abrir ficheiro para autenticar"
        )
        if not src:
            return
        dst = filedialog.asksaveasfilename(
            initialdir=BASE_DIR,
            defaultextension=".mac",
            filetypes=[("Ficheiros MAC","*.mac")],
            title="Guardar MAC como"
        )
        if dst:
            funcoes.autenticar_ficheiro(src, dst)

    def save_authenticated(self):
        src = filedialog.askopenfilename(
            initialdir=BASE_DIR,
            title="Abrir MAC para verificar"
        )
        if not src:
            return
        dst = filedialog.asksaveasfilename(
            initialdir=BASE_DIR,
            defaultextension=".txt",
            filetypes=[("Ficheiros de texto","*.txt")],
            title="Guardar se autenticado"
        )
        if dst:
            funcoes.guardar_se_autenticado(src, dst, src.replace(".mac", ".mac.key.txt"))

    def sign_file(self):
        src = filedialog.askopenfilename(
            initialdir=BASE_DIR,
            title="Abrir ficheiro para assinar"
        )
        if src:
            funcoes.assinar_ficheiro(src)

    def verify_signature(self):
        src = filedialog.askopenfilename(
            initialdir=BASE_DIR,
            title="Abrir ficheiro para verificar assinatura"
        )
        if not src:
            return
        sig = filedialog.askopenfilename(
            initialdir=BASE_DIR,
            title="Abrir assinatura (.sig)",
            filetypes=[("Assinaturas","*.sig")]   
        )
        if sig:
            funcoes.verificar_assinatura(src, sig)

    def delete_file(self):
        file_path = filedialog.askopenfilename(
            initialdir=BASE_DIR,
            title="Selecione o ficheiro para eliminar",
            filetypes=[("Todos os ficheiros","*.*")]
        )
        if not file_path:
            return
        confirmar = self.ask_yes_no_pt(
            "Confirmação",
            f"Deseja realmente eliminar o ficheiro '{os.path.basename(file_path)}'?"
        )
        if confirmar:
            try:
                os.remove(file_path)
                messagebox.showinfo("Sucesso", f"Ficheiro '{os.path.basename(file_path)}' eliminado com sucesso.")
            except Exception as e:
                messagebox.showerror("Erro", f"Não foi possível eliminar o ficheiro: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureEditorApp(root)
    root.mainloop()