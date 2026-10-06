import getpass
import hashlib
import json
import os
import pathlib
import sys
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


GENESIS_HASH = "0" * 64
ENCRYPTION_MAGIC = b"IDSENC1"


def calculate_sha256(file_path, chunk_size=1 << 20):
    hash_object = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)

            if not chunk:
                break

            hash_object.update(chunk)

    return hash_object.hexdigest()


def load_or_create_keys(key_directory):
    key_directory = pathlib.Path(key_directory)

    key_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    private_key_path = (
        key_directory / "ed25519_private.pem"
    )

    public_key_path = (
        key_directory / "ed25519_public.pem"
    )

    if private_key_path.exists():

        private_key = serialization.load_pem_private_key(
            private_key_path.read_bytes(),
            password=None
        )

    else:

        private_key = Ed25519PrivateKey.generate()

        private_key_bytes = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        private_key_path.write_bytes(
            private_key_bytes
        )

        os.chmod(
            private_key_path,
            0o600
        )

        public_key = private_key.public_key()

        public_key_bytes = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_key_path.write_bytes(
            public_key_bytes
        )

    public_key = serialization.load_pem_public_key(
        public_key_path.read_bytes()
    )

    return private_key, public_key


def build_manifest(pcap_directory):
    pcap_directory = pathlib.Path(pcap_directory)

    files = {}

    for file_path in sorted(pcap_directory.iterdir()):

        if file_path.suffix in (".pcap", ".pcapng"):
            files[file_path.name] = calculate_sha256(
                file_path
            )

    manifest = {
        "created": time.time(),
        "algorithm": "sha256",
        "files": files,
    }

    return json.dumps(
        manifest,
        sort_keys=True,
        indent=1
    ).encode()


def sign_manifest(
    pcap_directory,
    key_directory,
    output_prefix
):
    private_key, _ = load_or_create_keys(
        key_directory
    )

    manifest = build_manifest(
        pcap_directory
    )

    output_prefix = pathlib.Path(
        output_prefix
    )

    manifest_path = output_prefix.with_suffix(
        ".json"
    )

    signature_path = output_prefix.with_suffix(
        ".sig"
    )

    manifest_path.write_bytes(
        manifest
    )

    signature = private_key.sign(
        manifest
    )

    signature_path.write_bytes(
        signature
    )

    return json.loads(manifest)


def verify_manifest(
    pcap_directory,
    key_directory,
    manifest_prefix
):
    pcap_directory = pathlib.Path(
        pcap_directory
    )

    manifest_prefix = pathlib.Path(
        manifest_prefix
    )

    problems = []

    _, public_key = load_or_create_keys(
        key_directory
    )

    manifest_path = manifest_prefix.with_suffix(
        ".json"
    )

    signature_path = manifest_prefix.with_suffix(
        ".sig"
    )

    manifest = manifest_path.read_bytes()

    signature = signature_path.read_bytes()

    try:

        public_key.verify(
            signature,
            manifest
        )

    except InvalidSignature:

        return False, [
            "manifest signature INVALID"
        ]

    manifest_data = json.loads(
        manifest
    )

    recorded_files = manifest_data["files"]

    files_on_disk = {
        file_path.name
        for file_path in pcap_directory.iterdir()
        if file_path.suffix in (".pcap", ".pcapng")
    }

    for file_name, recorded_hash in recorded_files.items():

        file_path = (
            pcap_directory / file_name
        )

        if not file_path.exists():

            problems.append(
                f"{file_name}: missing"
            )

        else:

            current_hash = calculate_sha256(
                file_path
            )

            if current_hash != recorded_hash:

                problems.append(
                    f"{file_name}: SHA-256 mismatch"
                )

    recorded_file_names = set(
        recorded_files
    )

    extra_files = (
        files_on_disk - recorded_file_names
    )

    for file_name in sorted(extra_files):

        problems.append(
            f"{file_name}: not in signed manifest"
        )

    return (
        len(problems) == 0,
        problems
    )


def initialize_alert_table(connection):

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pcap_file TEXT,
            attack_type TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            first_ts REAL,
            last_ts REAL,
            evidence TEXT,
            body TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        )
        """
    )


def add_alert(connection, alert):

    alert_body = json.dumps(
        alert,
        sort_keys=True
    )

    previous_row = connection.execute(
        """
        SELECT entry_hash
        FROM alerts
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    if previous_row:
        previous_hash = previous_row[0]
    else:
        previous_hash = GENESIS_HASH

    data_to_hash = (
        previous_hash + alert_body
    ).encode()

    entry_hash = hashlib.sha256(
        data_to_hash
    ).hexdigest()

    connection.execute(
        """
        INSERT INTO alerts (
            pcap_file,
            attack_type,
            src_ip,
            dst_ip,
            first_ts,
            last_ts,
            evidence,
            body,
            prev_hash,
            entry_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert["pcap_file"],
            alert["attack_type"],
            alert["src_ip"],
            alert["dst_ip"],
            alert["first_ts"],
            alert["last_ts"],
            alert["evidence"],
            alert_body,
            previous_hash,
            entry_hash,
        )
    )


def verify_alert_chain(connection):

    previous_hash = GENESIS_HASH

    rows = connection.execute(
        """
        SELECT
            id,
            body,
            prev_hash,
            entry_hash
        FROM alerts
        ORDER BY id
        """
    )

    for row_id, body, stored_previous_hash, stored_entry_hash in rows:

        if stored_previous_hash != previous_hash:
            return False, row_id

        calculated_hash = hashlib.sha256(
            (
                stored_previous_hash + body
            ).encode()
        ).hexdigest()

        if calculated_hash != stored_entry_hash:
            return False, row_id

        previous_hash = stored_entry_hash

    return True, None


def derive_encryption_key(
    password,
    salt
):
    key_derivation = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 15,
        r=8,
        p=1
    )

    return key_derivation.derive(
        password
    )


def encrypt_file(
    source_path,
    destination_path,
    password
):
    salt = os.urandom(16)
    nonce = os.urandom(12)

    source_name = pathlib.Path(
        source_path
    ).name

    additional_data = source_name.encode()

    source_data = pathlib.Path(
        source_path
    ).read_bytes()

    encryption_key = derive_encryption_key(
        password,
        salt
    )

    encrypted_data = AESGCM(
        encryption_key
    ).encrypt(
        nonce,
        source_data,
        additional_data
    )

    additional_data_length = len(
        additional_data
    ).to_bytes(2, "big")

    encrypted_file = (
        ENCRYPTION_MAGIC
        + additional_data_length
        + additional_data
        + salt
        + nonce
        + encrypted_data
    )

    pathlib.Path(
        destination_path
    ).write_bytes(
        encrypted_file
    )


def decrypt_file(
    source_path,
    password
):
    encrypted_file = pathlib.Path(
        source_path
    ).read_bytes()

    if not encrypted_file.startswith(
        ENCRYPTION_MAGIC
    ):
        raise ValueError(
            "not an IDS-encrypted file"
        )

    offset = len(
        ENCRYPTION_MAGIC
    )

    additional_data_length = int.from_bytes(
        encrypted_file[
            offset:offset + 2
        ],
        "big"
    )

    offset += 2

    additional_data = encrypted_file[
        offset:offset + additional_data_length
    ]

    offset += additional_data_length

    salt = encrypted_file[
        offset:offset + 16
    ]

    offset += 16

    nonce = encrypted_file[
        offset:offset + 12
    ]

    offset += 12

    encrypted_data = encrypted_file[
        offset:
    ]

    encryption_key = derive_encryption_key(
        password,
        salt
    )

    try:

        decrypted_data = AESGCM(
            encryption_key
        ).decrypt(
            nonce,
            encrypted_data,
            additional_data
        )

        return decrypted_data

    except InvalidTag:

        raise ValueError(
            "decryption failed: wrong password or file was tampered with"
        )


def get_password():

    password = os.environ.get(
        "IDS_PASSWORD"
    )

    if not password:
        password = getpass.getpass(
            "Password: "
        )

    return password.encode()


def main():

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]

    if command == "sign":

        manifest = sign_manifest(
            sys.argv[2],
            sys.argv[3],
            sys.argv[4]
        )

        print(
            f"signed manifest for {len(manifest['files'])} files"
        )

    elif command == "verify":

        success, problems = verify_manifest(
            sys.argv[2],
            sys.argv[3],
            sys.argv[4]
        )

        if success:
            print(
                "OK: all PCAPs match the signed manifest"
            )

        else:
            print("FAILED:")

            for problem in problems:
                print(
                    f"  {problem}"
                )

        sys.exit(
            0 if success else 2
        )

    elif command == "encrypt":

        password = get_password()

        encrypt_file(
            sys.argv[2],
            sys.argv[3],
            password
        )

        print(
            "encrypted ->",
            sys.argv[3]
        )

    elif command == "decrypt":

        password = get_password()

        decrypted_data = decrypt_file(
            sys.argv[2],
            password
        )

        pathlib.Path(
            sys.argv[3]
        ).write_bytes(
            decrypted_data
        )

        print(
            "decrypted ->",
            sys.argv[3]
        )

    else:

        print(__doc__)


if __name__ == "__main__":
    main()