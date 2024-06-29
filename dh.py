from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


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


def generate_dh_parameters():
    # Estos parámetros pueden ser guardados y reutilizados
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Serialización correcta de los parámetros DH
    pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
    )

    with open("dh_parameters.pem", "wb") as f:
        f.write(pem)

    return parameters


def load_dh_parameters(file_path):
    with open(file_path, "rb") as f:
        pem_data = f.read()
    parameters = serialization.load_pem_parameters(pem_data)
    return parameters


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


if __name__ == "__main__":
    # Ejemplo de uso
    print("Ejemplo de uso de Diffie-Hellman")
    parameters = generate_dh_parameters()
    print("Parámetros DH generados correctamente")

    parametersA = load_dh_parameters("dh_parameters.pem")
    print("Parámetros DH cargados correctamente")
    dh_private_A, dh_public_KA = generate_dh_keys(parametersA, "a")
    print("Claves DH generadas correctamente")

    parametersB = load_dh_parameters("dh_parameters.pem")
    print("Parámetros DH cargados correctamente")
    dh_private_B, dh_public_KB = generate_dh_keys(parametersB, "b")
    print("Claves DH generadas correctamente")
    
    peer_dh_private_A_pem = load_private_key("dh_private_a.pem")
    peer_dh_public_KA_pem = load_public_key("dh_public_Ka.pem")
    peer_dh_private_B_pem = load_private_key("dh_private_b.pem")
    peer_dh_public_KB_pem = load_public_key("dh_public_Kb.pem")

    shared_secret_A_to_B = calculate_shared_secret(peer_dh_private_A_pem, peer_dh_public_KB_pem)
    print("La clave secreta compartida de A a B es:", shared_secret_A_to_B.hex())
    print(
        "Longitud de la clave secreta compartida de A a B:",
        len(shared_secret_A_to_B),
        "bytes",
    )

    shared_secret_B_to_A = calculate_shared_secret(peer_dh_private_B_pem, peer_dh_public_KA_pem)
    print("La clave secreta compartida de B a A es:", shared_secret_B_to_A.hex())
    print(
        "Longitud de la clave secreta compartida de B a A:",
        len(shared_secret_B_to_A),
        "bytes",
    )

    print(
        "¿Las claves secretas compartidas son iguales?",
        shared_secret_A_to_B == shared_secret_B_to_A,
    )

    print("\nDerivación de claves AES-128 a partir de las claves secretas compartidas")
    derived_key_AES = derive_shared_secret(shared_secret_A_to_B, b"KEY")
    print("La clave derivada para AES-128:", derived_key_AES.hex())
    print("Longitud de la clave derivada de A a B:", len(derived_key_AES), "bytes")

    derived_key_IV = derive_shared_secret(shared_secret_B_to_A, b"IV")
    print("La clave derivada para vector de inicialización:", derived_key_IV.hex())
    print("Longitud de la clave derivada de B a A:", len(derived_key_IV), "bytes")

    derived_key_None = derive_shared_secret(shared_secret_B_to_A)
    print("La clave derivada para vector de inicialización:", derived_key_None.hex())
    print("Longitud de la clave derivada de B a A:", len(derived_key_None), "bytes")