from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox, Text, Scrollbar
import base64, os, webbrowser

# Global variables to store the last used file and mode of operation
last_parameters_path = ""
last_file_path = ""
last_mode = "ECB"


def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    return private_key


def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    return public_key


def load_dh_parameters(file_path):
    with open(file_path, "rb") as f:
        pem_data = f.read()
    parameters = serialization.load_pem_parameters(pem_data)
    return parameters


def open_file(file_path):
    try:
        # Tries to open the file with the default application
        if os.name == "nt":  # Windows
            os.startfile(file_path)
        else:
            # Unix based systems
            webbrowser.open(file_path)
    except Exception as e:
        print(f"Error opening the file: {e}")


def read_file(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        return content
    except Exception as e:
        print(f"Error reading the file: {e}")
        messagebox.showwarning("Read error", f"Error reading the file. {e}")
        return None


def write_file(file_path, data, suffix=None, open_new_file=True):
    file_path_base = file_path.rsplit(".", 1)[-2]
    extension = file_path.rsplit(".", 1)[-1]
    new_file_path = f"{file_path_base}{('_' + suffix) if suffix is not None and suffix != '' else ''}.{extension}"
    try:
        with open(new_file_path, "wb") as f:
            f.write(data)
        print(f"File saved as: {new_file_path}")
        messagebox.showinfo(
            "File saved",
            f"File saved as: {os.path.basename(new_file_path)}",
        )
        if open_new_file:
            open_file(new_file_path)
        return new_file_path
    except Exception as e:
        print(f"Error saving the file: {e}")
        messagebox.showwarning("Save error", f"Error saving the file. {e}")
        return None


def extract_content(content, header_size, footer_size):
    if content is not None:
        header = content[:header_size] if header_size > 0 else b""
        footer = content[-footer_size:] if footer_size > 0 else b""
        data = (
            content[header_size:-footer_size]
            if footer_size > 0
            else content[header_size:]
        )
        return header, data, footer
    else:
        return None, None, None


def generate_dh_parameters(suffix=None):
    global last_parameters_path
    # These parameters can be saved and reused
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Proper serialization of DH parameters
    pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
    )

    last_parameters_path = write_file("dh_parameters.pem", pem, suffix, False)

    messagebox.showinfo("Parameters generated", "DH parameters generated successfully.")
    return parameters


# Generation of public and private keys
def generate_dh_keys(parameters_path, suffix):
    if not verify_parameters_dh_keys(parameters_path):
        return None, None
    else:
        parameters = load_dh_parameters(parameters_path)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        # Serialization of the private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        write_file("dh_private.pem", private_pem, suffix, False)

        # Serialization of the public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        write_file("dh_public.pem", public_pem, suffix, False)

        messagebox.showinfo("Keys generated", "DH keys generated successfully.")
        return private_key, public_key


# Function modified to calculate the shared secret and derive an AES-128 key
def derive_shared_secret(private_key_path, public_key_path, info=None, suffix=None):
    if not verify_parameters_dh_shared_key(private_key_path, public_key_path):
        return None, None
    else:
        private_key = load_private_key(private_key_path)
        public_key = load_public_key(public_key_path)
        shared_key = private_key.exchange(public_key)

        # Derivation of the AES-128 key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # Length for AES-128
            salt=None,
            info=info,
            backend=default_backend(),
        ).derive(shared_key)

        write_file("shared_key.hex", shared_key.hex().encode("utf-8"), suffix)
        write_file("derived_key.hex", derived_key.hex().encode("utf-8"), suffix)

        messagebox.showinfo(
            "Shared secret generated",
            "Shared secret & derived key generated successfully.",
        )
        return shared_key, derived_key


def verify_parameters_dh_keys(parameters_path):
    root = tk.Tk()
    root.withdraw()  # Hide the main Tkinter window
    if not parameters_path:
        messagebox.showwarning("Warning", "Please select the dh parameters file.")
        return False
    if not os.path.exists(parameters_path):
        messagebox.showwarning("Warning", "The dh parameters file does not exist.")
        return False
    return True


def verify_parameters_dh_shared_key(private_key_path, public_key_path):
    root = tk.Tk()
    root.withdraw()  # Hide the main Tkinter window
    if not private_key_path:
        messagebox.showwarning("Warning", "Please select the dh private key file.")
        return False
    if not os.path.exists(private_key_path):
        messagebox.showwarning("Warning", "The dh private key file does not exist.")
        return False
    if not public_key_path:
        messagebox.showwarning("Warning", "Please select the dh public key file.")
        return False
    if not os.path.exists(public_key_path):
        messagebox.showwarning("Warning", "The dh public key file does not exist.")
        return False
    return True


def sign_file(file_path, private_key_path):
    global last_file_path
    if not verify_parameters_rsa_sv(file_path, private_key_path):
        return
    try:
        private_key = load_private_key(private_key_path)
        content = read_file(file_path)
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(content)
        hash_value = digest.finalize()
        signature = private_key.sign(
            hash_value,
            padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=0),
            hashes.SHA3_256(),
        )
        encoded_signature = base64.b64encode(signature)
        last_file_path = write_file(
            file_path, content + b"\n" + encoded_signature, "fRSA"
        )
        messagebox.showinfo("Signature", "File signed successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to sign the file.\n{e}")


def verify_signature(file_path, public_key_path):
    if not verify_parameters_rsa_sv(file_path, public_key_path):
        return
    try:
        public_key = load_public_key(public_key_path)
        content = read_file(file_path)
        _, plaintext, signature_base64 = extract_content(content, 0, 345)
        signature = base64.b64decode(signature_base64.strip())
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(plaintext)
        hash_value = digest.finalize()
        public_key.verify(
            signature,
            hash_value,
            padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=0),
            hashes.SHA3_256(),
        )
        messagebox.showinfo("Verification", "The signature is valid :)")
    except Exception as e:
        messagebox.showinfo("Verification", f"Signature verification failed :(\n{e}")


def verify_parameters_rsa_sv(file_path, key):
    root = tk.Tk()
    root.withdraw()  # Hide the main Tkinter window
    if not file_path:
        messagebox.showwarning("Warning", "Please select a file.")
        return False
    if not os.path.exists(file_path):
        messagebox.showwarning("Warning", "The file does not exist.")
        return False
    if not key:
        messagebox.showwarning("Warning", "Please select a key.")
        return False
    if not os.path.exists(key):
        messagebox.showwarning("Warning", "The key does not exist.")
        return False
    return True


def aes_encrypt(plaintext, key, mode, c0=None):
    try:
        backend = default_backend()
        if mode == "ECB":
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        else:
            cipher = Cipher(
                algorithms.AES(key), getattr(modes, mode)(c0), backend=backend
            )

        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return ciphertext
    except Exception as e:
        print(f"Cipher error: {e}")
        messagebox.showwarning("Cipher error", "Error cipherying the file.")
        return None


def aes_decrypt(ciphertext, key, mode, c0=None):
    backend = default_backend()
    try:
        if mode == "ECB":
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        else:
            cipher = Cipher(
                algorithms.AES(key), getattr(modes, mode)(c0), backend=backend
            )

        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        try:
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()
            return plaintext
        except ValueError:
            # Si hay un error de padding, devuelve el texto cifrado que no se pudo desempaquetar correctamente
            print(
                "Warning: Padding error detected in decryption. Data may be corrupted or incomplete."
            )
            return plaintext_padded  # Retornar los datos sin desempaquetar puede ser inútil si están muy corruptos.

    except Exception as e:
        print(f"Decipher error: {e}")
        messagebox.showwarning("Decipher error", "Error decipherying the file.")
        return None


def encrypt_file(file_path, key, mode, c0):
    global last_mode, last_file_path
    key, c0, mode = verify_parameters_aes(file_path, key, mode, c0)
    if key is None:
        return
    content = read_file(file_path)
    extension = file_path.rsplit(".", 1)[-1]
    header, plaintext, _ = (
        extract_content(content, 54, 0)
        if extension == "bmp"
        else extract_content(content, 0, 0)
    )
    ciphertext = aes_encrypt(plaintext, key, mode, c0)
    last_file_path = write_file(file_path, header + ciphertext, f"e{mode}")
    last_mode = mode


def decrypt_file(file_path, key, mode, c0):
    global last_mode, last_file_path
    key, c0, mode = verify_parameters_aes(file_path, key, mode, c0)
    if key is None:
        return
    content = read_file(file_path)
    extension = file_path.rsplit(".", 1)[-1]
    header, ciphertext, _ = (
        extract_content(content, 54, 0)
        if extension == "bmp"
        else extract_content(content, 0, 0)
    )
    plaintext = aes_decrypt(ciphertext, key, mode, c0)
    last_file_path = write_file(file_path, header + plaintext, f"d{mode}")
    last_mode = mode


def verify_parameters_aes(file_path, key, mode, c0):
    root = tk.Tk()
    root.withdraw()  # Hide the main Tkinter window
    if not file_path:
        messagebox.showwarning("Warning", "Please select a file.")
        return None, None, None
    if not os.path.exists(file_path):
        messagebox.showwarning("Warning", "The file does not exist.")
        return None, None, None
    if mode not in ["CBC", "CFB", "OFB", "ECB"]:
        messagebox.showwarning("Warning", "Please select a valid mode.")
        return None, None, None
    try:
        key = bytes.fromhex(key)
        if len(key) != 16:
            messagebox.showwarning("Warning", "The key must be 16 bytes long.")
            return None, None, None
    except ValueError as e:
        messagebox.showwarning("Warning", f"Invalid key hex string: {e}")
        return None, None, None
    try:
        if mode != "ECB":  # Only necessary if using modes that require an IV
            c0 = bytes.fromhex(c0)
            if len(c0) != 16:
                messagebox.showwarning(
                    "Warning", "The initialization vector c0 must be 16 bytes long."
                )
                return None, None, None
        else:
            c0 = None
    except ValueError as e:
        messagebox.showwarning("Warning", f"Invalid IV hex string: {e}")
        return None, None, None

    return key, c0, mode


def main_menu():
    main_menu_window = tk.Tk()
    main_menu_window.title("Crypto Tools")
    main_menu_window.geometry("400x200")  # Adjust size to fit all buttons

    # Central container for buttons
    button_frame = tk.Frame(main_menu_window)
    button_frame.pack(pady=30)  # Center the frame vertically and add some padding

    # Button for DH parameters
    tk.Button(
        button_frame,
        text="DH parameters",
        command=lambda: dh_menu(main_menu_window, "Generate parameters g, n"),
        bg="#de45c4",
        width=20,
    ).pack(side=tk.LEFT, padx=10)

    # Button for DH keys
    tk.Button(
        button_frame,
        text="DH keys",
        command=lambda: dh_menu(main_menu_window, "Generate dh keys"),
        bg="#ac45de",
        width=20,
    ).pack(side=tk.LEFT, padx=10)

    # Button for DH shared secret
    tk.Button(
        button_frame,
        text="DH shared secret",
        command=lambda: dh_menu(main_menu_window, "Generate secret shared key"),
        bg="#4577de",
        width=20,
    ).pack(side=tk.LEFT, padx=10)

    # Button for Signing
    tk.Button(
        button_frame,
        text="Sign",
        command=lambda: sign_verify_menu(main_menu_window, "Sign"),
        bg="#ff7e38",
        width=20,
    ).pack(side=tk.LEFT, padx=10)

    # Button for Verification
    tk.Button(
        button_frame,
        text="Verify",
        command=lambda: sign_verify_menu(main_menu_window, "Verify"),
        bg="#38b9ff",
        width=20,
    ).pack(side=tk.LEFT, padx=10)

    # Button for AES Cipher
    tk.Button(
        button_frame,
        text="Cipher",
        command=lambda: cipher_decipher_menu(main_menu_window, "Cipher"),
        bg="#e06666",
        width=20,
    ).pack(side=tk.LEFT, padx=10)

    # Button for AES Decipher
    tk.Button(
        button_frame,
        text="Decipher",
        command=lambda: cipher_decipher_menu(main_menu_window, "Decipher"),
        bg="#93c47d",
        width=20,
    ).pack(side=tk.LEFT, padx=10)

    main_menu_window.mainloop()


def dh_menu(parent_window, action):
    parent_window.withdraw()
    action_window = tk.Toplevel()
    action_window.title(f"{action} file")
    action_window.geometry("400x300")

    frame = tk.Frame(action_window)
    frame.pack(padx=10, pady=10)

    if action == "Generate parameters g, n":
        action_window.geometry("400x150")

        # Text input for the pem files suffix
        tk.Label(frame, text="Parameters file suffix:").pack(anchor="w")
        suffix_entry = tk.Entry(frame, width=40)
        suffix_entry.pack(fill="x", expand=True)

        # Buttons
        button_color = "#de45c4"
        command = lambda: generate_dh_parameters(suffix=suffix_entry.get())

    elif action == "Generate dh keys":
        # File selection for DH parameters
        tk.Label(frame, text="DH parameters path:").pack(anchor="w")
        parameters_path_text = Text(frame, height=1, width=40)
        parameters_path_text.pack(fill="x", expand=True)
        parameters_path_text.insert(tk.END, last_parameters_path)
        scrollbar = Scrollbar(
            frame, orient="horizontal", command=parameters_path_text.xview
        )
        parameters_path_text.configure(wrap="none", xscrollcommand=scrollbar.set)
        scrollbar.pack(fill="x")
        tk.Button(
            frame,
            text="Select File",
            command=lambda: select_file(
                parameters_path_text,
                [("PEM files", "*.pem;*.key"), ("All files", "*.*")],
            ),
        ).pack(anchor="e")

        # Text input for the pem files suffix
        tk.Label(frame, text="Keys file suffix:").pack(anchor="w")
        suffix_entry = tk.Entry(frame, width=40)
        suffix_entry.pack(fill="x", expand=True)

        # Buttons
        button_color = "#ac45de"
        command = lambda: generate_dh_keys(
            parameters_path=parameters_path_text.get("1.0", "end-1c"),
            suffix=suffix_entry.get(),
        )

    else:  # Generate secret shared key
        # File selection for DH private key
        tk.Label(frame, text="DH private key path:").pack(anchor="w")
        private_key_path_text = Text(frame, height=1, width=40)
        private_key_path_text.pack(fill="x", expand=True)
        scrollbar = Scrollbar(
            frame, orient="horizontal", command=private_key_path_text.xview
        )
        private_key_path_text.configure(wrap="none", xscrollcommand=scrollbar.set)
        scrollbar.pack(fill="x")
        tk.Button(
            frame,
            text="Select File",
            command=lambda: select_file(
                private_key_path_text,
                [("PEM files", "*.pem;*.key"), ("All files", "*.*")],
            ),
        ).pack(anchor="e")

        # File selection for DH public shared key
        tk.Label(frame, text="DH shared public key path:").pack(anchor="w")
        shared_public_key_path_text = Text(frame, height=1, width=40)
        shared_public_key_path_text.pack(fill="x", expand=True)
        scrollbar = Scrollbar(
            frame, orient="horizontal", command=shared_public_key_path_text.xview
        )
        shared_public_key_path_text.configure(wrap="none", xscrollcommand=scrollbar.set)
        scrollbar.pack(fill="x")
        tk.Button(
            frame,
            text="Select File",
            command=lambda: select_file(
                shared_public_key_path_text,
                [("PEM files", "*.pem;*.key"), ("All files", "*.*")],
            ),
        ).pack(anchor="e")

        # Text input for the hex file suffix
        tk.Label(frame, text="Shared secret suffix:").pack(anchor="w")
        suffix_entry = tk.Entry(frame, width=40)
        suffix_entry.pack(fill="x", expand=True)

        # Buttons
        button_color = "#4577de"
        command = lambda: derive_shared_secret(
            private_key_path=private_key_path_text.get("1.0", "end-1c"),
            public_key_path=shared_public_key_path_text.get("1.0", "end-1c"),
            info=b"AES-128",
            suffix=suffix_entry.get(),
        )

    # Buttons frame
    button_frame = tk.Frame(frame)
    button_frame.pack(pady=10)
    tk.Button(
        button_frame,
        text="Back",
        command=lambda: close_window(action_window, parent_window),
    ).pack(side=tk.LEFT, padx=10, pady=10)
    tk.Button(button_frame, text=action, command=command, bg=button_color).pack(
        side=tk.LEFT, padx=10, pady=10
    )


def cipher_decipher_menu(parent_window, action):
    parent_window.withdraw()
    action_window = tk.Toplevel()
    action_window.title(f"{action} file")
    action_window.geometry("400x450")

    frame = tk.Frame(action_window)
    frame.pack(padx=10, pady=10)

    # File path
    tk.Label(frame, text="File path:").pack(anchor="w")
    file_path_text = Text(frame, height=1, width=40)
    file_path_text.pack(fill="x", expand=True)
    file_path_text.insert(tk.END, last_file_path)
    scrollbar = Scrollbar(frame, orient="horizontal", command=file_path_text.xview)
    file_path_text.configure(wrap="none", xscrollcommand=scrollbar.set)
    scrollbar.pack(fill="x")
    tk.Button(
        frame, text="Select File", command=lambda: select_file(file_path_text)
    ).pack(anchor="e")

    # Key
    tk.Label(frame, text="Key (K) [32 hex characters]:").pack(anchor="w")
    key_entry = tk.Entry(frame, width=40)
    key_entry.pack(fill="x", expand=True)
    tk.Button(
        frame,
        text="Load from file",
        command=lambda: select_file_and_load_content(
            key_entry, [("Hex files", "*.hex"), ("All files", "*.*")]
        ),
    ).pack(anchor="e")

    # Mode of operation
    tk.Label(frame, text="Mode of operation:").pack(anchor="w")
    modes = {"ECB": "ECB", "CBC": "CBC", "CFB": "CFB", "OFB": "OFB"}
    mode_var = tk.StringVar(
        value=last_mode if last_mode in modes.values() else list(modes.values())[-1]
    )
    modes_frame = tk.Frame(frame)
    modes_frame.pack(fill="x", expand=True)
    for mode, value in modes.items():
        tk.Radiobutton(
            modes_frame,
            text=mode,
            variable=mode_var,
            value=value,
            command=lambda: update_iv_entry_state(iv_entry, load_iv_button, mode_var),
        ).pack()  # side="left"

    # Initialization Vector
    tk.Label(frame, text="Initialization Vector (C0 or IV) [32 hex characters]:").pack(
        anchor="w"
    )
    iv_entry = tk.Entry(frame, width=40)
    iv_entry.pack(fill="x", expand=True)
    load_iv_button = tk.Button(
        frame,
        text="Load from file",
        command=lambda: select_file_and_load_content(
            iv_entry, [("Hex files", "*.hex"), ("All files", "*.*")]
        ),
    )
    load_iv_button.pack(anchor="e")
    update_iv_entry_state(iv_entry, load_iv_button, mode_var)

    # Action buttons
    button_frame = tk.Frame(frame)
    button_frame.pack(pady=10)

    if action == "Cipher":
        button_color = "#e06666"
        command = lambda: encrypt_file(
            file_path_text.get("1.0", "end-1c"),
            key_entry.get(),
            mode_var.get(),
            iv_entry.get(),
        )
    else:  # Decrypt
        button_color = "#93c47d"
        command = lambda: decrypt_file(
            file_path_text.get("1.0", "end-1c"),
            key_entry.get(),
            mode_var.get(),
            iv_entry.get(),
        )
    tk.Button(
        button_frame,
        text="Back",
        command=lambda: close_window(action_window, parent_window),
    ).pack(side=tk.LEFT, padx=10, pady=10)
    tk.Button(button_frame, text=action, command=command, bg=button_color).pack(
        side=tk.LEFT, padx=10, pady=10
    )


def sign_verify_menu(parent_window, action):
    parent_window.withdraw()
    action_window = tk.Toplevel()
    action_window.title(f"{action} file")
    action_window.geometry("400x300")

    frame = tk.Frame(action_window)
    frame.pack(padx=10, pady=10)

    # File path
    tk.Label(frame, text="File path:").pack(anchor="w")
    file_path_text = Text(frame, height=1, width=40)
    file_path_text.pack(fill="x", expand=True)
    file_path_text.insert(tk.END, last_file_path)
    scrollbar = Scrollbar(frame, orient="horizontal", command=file_path_text.xview)
    file_path_text.configure(wrap="none", xscrollcommand=scrollbar.set)
    scrollbar.pack(fill="x")
    tk.Button(
        frame, text="Select File", command=lambda: select_file(file_path_text)
    ).pack(anchor="e")

    # Key path
    tk.Label(frame, text="Key path:").pack(anchor="w")
    key_text = Text(frame, height=1, width=40)
    key_text.pack(fill="x", expand=True)
    key_scrollbar = Scrollbar(frame, orient="horizontal", command=key_text.xview)
    key_text.configure(wrap="none", xscrollcommand=key_scrollbar.set)
    key_scrollbar.pack(fill="x")
    tk.Button(
        frame,
        text="Select Key",
        command=lambda: select_file(
            key_text, [("PEM files", "*.pem;*.key"), ("All files", "*.*")]
        ),
    ).pack(anchor="e")

    # Action buttons
    button_frame = tk.Frame(frame)
    button_frame.pack(pady=10)

    if action == "Sign":
        button_text = "Sign File"
        button_color = "#ff7e38"
        command = lambda: sign_file(
            file_path_text.get("1.0", "end-1c"), key_text.get("1.0", "end-1c")
        )
    else:  # Verify
        button_text = "Verify File"
        button_color = "#38b9ff"
        command = lambda: verify_signature(
            file_path_text.get("1.0", "end-1c"), key_text.get("1.0", "end-1c")
        )

    tk.Button(
        button_frame,
        text="Back",
        command=lambda: close_window(action_window, parent_window),
    ).pack(side=tk.LEFT, padx=10, pady=10)
    tk.Button(button_frame, text=button_text, command=command, bg=button_color).pack(
        side=tk.LEFT, padx=10, pady=10
    )


def update_iv_entry_state(iv_entry, load_iv_button, mode_var):
    if mode_var.get() == "ECB":
        iv_entry.config(state="disabled")
        load_iv_button.config(state="disabled")
    else:
        iv_entry.config(state="normal")
        load_iv_button.config(state="normal")


def select_file(text_widget, filetypes=[("All files", "*.*")]):
    file_path = filedialog.askopenfilename(filetypes=filetypes)
    text_widget.delete("1.0", tk.END)
    text_widget.insert("1.0", file_path)


def select_file_and_load_content(entry_widget, filetypes=[("All files", "*.*")]):
    file_path = filedialog.askopenfilename(filetypes=filetypes)
    if file_path:
        data = read_file(file_path)
        if data is not None:
            string = data.decode("utf-8")
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, string)
        else:
            messagebox.showerror("Error", "Failed to load data from file.")


def close_window(child_window, parent_window):
    child_window.destroy()
    parent_window.deiconify()


if __name__ == "__main__":
    main_menu()
