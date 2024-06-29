from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox, Text, Scrollbar
import os
import subprocess


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


def generate_dh_parameters(suffix=None):
    # Estos parámetros pueden ser guardados y reutilizados
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Serialización correcta de los parámetros DH
    pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
    )

    with open(
        f"dh_parameters_{suffix}.pem" if suffix is not None else "dh_parameters.pem",
        "wb",
    ) as f:
        f.write(pem)

    return parameters


def load_dh_parameters(file_path):
    with open(file_path, "rb") as f:
        pem_data = f.read()
    parameters = serialization.load_pem_parameters(pem_data)
    return parameters


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


def read_file(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        return content
    except Exception as e:
        print(f"Error reading the file: {e}")
        messagebox.showwarning("Read error", f"Error reading the file. {e}")
        return None


def write_file(file_path, data, sufix=None):
    file_path_base = file_path.rsplit(".", 1)[-2]
    extension = file_path.rsplit(".", 1)[-1]
    new_file_path = (
        f"{file_path_base}{('_' + sufix) if sufix is not None else ''}.{extension}"
    )
    try:
        with open(new_file_path, "wb") as f:
            f.write(data)
        print(f"File saved as: {new_file_path}")
        messagebox.showinfo(
            "File saved",
            f"File saved as: {os.path.basename(new_file_path)}",
        )
        subprocess.run(["start", new_file_path], shell=True)
        return new_file_path
    except Exception as e:
        print(f"Error saving the file: {e}")
        messagebox.showwarning("Save error", f"Error saving the file. {e}")
        return None


# Generación de claves pública y privada
def generate_dh_keys(parameters, suffix):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    # Serialización de la clave privada
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(f"dh_private_{suffix}.pem", "wb") as f:
        f.write(private_pem)

    # Serialización de la clave pública
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(f"dh_public_K{suffix}.pem", "wb") as f:
        f.write(public_pem)

    return private_key, public_key


# Función para calcular la clave secreta compartida
def calculate_shared_secret(private_key, public_key):
    shared_key = private_key.exchange(public_key)
    return shared_key


# Función modificada para calcular la clave secreta compartida y derivar una clave AES-128
def derive_shared_secret(shared_key, info=None):

    # Derivación de la clave AES-128 usando HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # Longitud para AES-128
        salt=None,
        info=info,
        backend=default_backend(),
    ).derive(shared_key)

    return derived_key


def read_file(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        return content
    except Exception as e:
        print(f"Error reading the file: {e}")
        messagebox.showwarning("Read error", f"Error reading the file. {e}")
        return None


def write_file(file_path, data, sufix=None):
    file_path_base = file_path.rsplit(".", 1)[-2]
    extension = file_path.rsplit(".", 1)[-1]
    new_file_path = (
        f"{file_path_base}{('_' + sufix) if sufix is not None else ''}.{extension}"
    )
    try:
        with open(new_file_path, "wb") as f:
            f.write(data)
        print(f"File saved as: {new_file_path}")
        messagebox.showinfo(
           "File saved",
           f"File saved as: {os.path.basename(new_file_path)}",
        )
        subprocess.run(["start", new_file_path], shell=True)
        return new_file_path
    except Exception as e:
        print(f"Error saving the file: {e}")
        messagebox.showwarning("Save error", f"Error saving the file. {e}")
        return None


def main_menu():
    main_menu_window = tk.Tk()
    main_menu_window.title("DH Key Exchange")
    main_menu_window.geometry("400x100")

    # Central container for buttons
    button_frame = tk.Frame(main_menu_window)
    button_frame.pack(pady=30)  # Center the frame vertically and add some padding

    # Parameters button
    tk.Button(
        button_frame,
        text="DH parameters",
        command=lambda: dh_menu(main_menu_window, "Generate parameters g, n"),
        bg="#de45c4",
        width=15,
    ).pack(
        side=tk.LEFT, padx=10
    )  # Add horizontal spacing between buttons

    # Keys button
    tk.Button(
        button_frame,
        text="DH keys",
        command=lambda: dh_menu(main_menu_window, "Generate dh keys"),
        bg="#ac45de",
        width=15,
    ).pack(
        side=tk.LEFT, padx=10
    )  # Add horizontal spacing between buttons

    # Shared key button
    tk.Button(
        button_frame,
        text="DH shared secret",
        command=lambda: dh_menu(main_menu_window, "Generate secret shared key"),
        bg="#4577de",
        width=15,
    ).pack(
        side=tk.LEFT, padx=10
    )  # Add horizontal spacing between buttons

    main_menu_window.mainloop()


def dh_menu(parent_window, action):
    parent_window.withdraw()
    action_window = tk.Toplevel()
    action_window.title(f"{action} File")
    action_window.geometry("400x450")

    frame = tk.Frame(action_window)
    frame.pack(padx=10, pady=10)

    if action == "Generate parameters g, n":
        # Text input for the pem files suffix

        # Buttons
        button_color = "#de45c4"
        command = lambda: generate_dh_parameters()
    elif action == "Generate dh keys":
        # File selection for DH parameters

        # Text input for the pem files suffix

        # Buttons
        button_color = "#ac45de"
        command = lambda: messagebox.showinfo("Keys", "This must generate the DH keys")
    else:  # Generate secret shared key
        # File selection for DH private key

        # File selection for DH public shared key

        # Text input for the hex file suffix

        # Buttons
        button_color = "#4577de"
        command = lambda: messagebox.showinfo(
            "Shared secret key",
            "This must generate the shared secret key and the derived key",
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