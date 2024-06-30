from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox, Text, Scrollbar
import os, webbrowser


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
        print(f"Error al abrir el archivo: {e}")


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
    # Estos parámetros pueden ser guardados y reutilizados
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Serialización correcta de los parámetros DH
    pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
    )

    write_file("dh_parameters.pem", pem, suffix, False)

    messagebox.showinfo("Parameters generated", "DH parameters generated successfully.")
    return parameters


# Generación de claves pública y privada
def generate_dh_keys(parameters_path, suffix):
    if not verify_parameters_dh_keys(parameters_path):
        return None, None
    else:
        parameters = load_dh_parameters(parameters_path)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        # Serialización de la clave privada
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        write_file("dh_private.pem", private_pem, suffix, False)

        # Serialización de la clave pública
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        write_file("dh_public.pem", public_pem, suffix, False)

        messagebox.showinfo("Keys generated", "DH keys generated successfully.")
        return private_key, public_key


# Función modificada para calcular la clave secreta compartida y derivar una clave AES-128
def derive_shared_secret(private_key_path, public_key_path, info=None, suffix=None):
    if not verify_parameters_dh_shared_key(private_key_path, public_key_path):
        return None, None
    else:
        private_key = load_private_key(private_key_path)
        public_key = load_public_key(public_key_path)
        shared_key = private_key.exchange(public_key)

        # Derivación de la clave AES-128 usando HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # Longitud para AES-128
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
    action_window.title(f"{action} file")
    action_window.geometry("400x300")

    frame = tk.Frame(action_window)
    frame.pack(padx=10, pady=10)

    if action == "Generate parameters g, n":
        action_window.geometry("400x150")
        # Text input for the pem files suffix
        # Suffix
        tk.Label(frame, text="Parameters file suffx:").pack(anchor="w")
        suffix_entry = tk.Entry(frame, width=40)
        suffix_entry.pack(fill="x", expand=True)

        # Buttons
        button_color = "#de45c4"
        command = lambda: generate_dh_parameters(suffix=suffix_entry.get())
    elif action == "Generate dh keys":
        # File selection for DH parameters
        # File path
        tk.Label(frame, text="DH parameters path:").pack(anchor="w")
        parameters_path_text = Text(frame, height=1, width=40)
        parameters_path_text.pack(fill="x", expand=True)
        # parameters_path_text.insert(tk.END, last_file_path)
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
        # Suffix
        tk.Label(frame, text="Keys file suffx:").pack(anchor="w")
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
        # File path
        tk.Label(frame, text="DH private key path:").pack(anchor="w")
        private_key_path_text = Text(frame, height=1, width=40)
        private_key_path_text.pack(fill="x", expand=True)
        # private_key_path_text.insert(tk.END, last_file_path)
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
        # File path
        tk.Label(frame, text="DH shared public key path:").pack(anchor="w")
        shared_public_key_path_text = Text(frame, height=1, width=40)
        shared_public_key_path_text.pack(fill="x", expand=True)
        # shared_public_key_path_text.insert(tk.END, last_file_path)
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
        # Suffix
        tk.Label(frame, text="Shared secret suffx:").pack(anchor="w")
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
