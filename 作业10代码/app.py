import argparse
import base64
import hashlib
import hmac
import json
import secrets
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pydantic import BaseModel, Field

CONFIG_PATH = Path("config.json")
MAGIC = b"LUMI"
HEADER_SUFFIX = ".hdr"
DATA_SUFFIX = ".enc"
PBKDF2_ROUNDS = 200_000
KEY_SIZE = 32


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def derive_key(password: str, salt: bytes, purpose: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt + b"|" + purpose, PBKDF2_ROUNDS, dklen=KEY_SIZE
    )


def password_verifier(password: str, salt: bytes) -> str:
    return hashlib.sha256(derive_key(password, salt, b"auth")).hexdigest()


class Cipher(BaseModel):
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        iv = secrets.token_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data, AES.block_size))

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        if len(data) < 2 * AES.block_size or (len(data) - AES.block_size) % AES.block_size:
            raise ValueError("invalid encrypted data")
        iv, ciphertext = data[: AES.block_size], data[AES.block_size :]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)


class Vault(BaseModel):
    username: str
    salt: str
    verifier: str
    vault: Path
    wrapped_master: str
    recovery_salt: str
    recovery_blob: str
    filelist: list[str] = Field(default_factory=list)

    @property
    def salt_bytes(self) -> bytes:
        return bytes.fromhex(self.salt)

    @property
    def recovery_salt_bytes(self) -> bytes:
        return bytes.fromhex(self.recovery_salt)

    def verify(self, username: str, password: str) -> bool:
        candidate = password_verifier(password, self.salt_bytes)
        return self.username == username and hmac.compare_digest(candidate, self.verifier)

    def unlock(self, password: str) -> bytes:
        if not hmac.compare_digest(password_verifier(password, self.salt_bytes), self.verifier):
            raise PermissionError("invalid password")
        return Cipher.decrypt(b64d(self.wrapped_master), derive_key(password, self.salt_bytes, b"kek"))

    def save(self) -> None:
        CONFIG_PATH.write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load(cls) -> "Vault":
        return cls.model_validate_json(CONFIG_PATH.read_text(encoding="utf-8"))

    @classmethod
    def create(cls, username: str, password: str, vault: Path, salt: bytes) -> tuple["Vault", str]:
        vault.mkdir(parents=True, exist_ok=True)
        master = secrets.token_bytes(KEY_SIZE)
        recovery_code = secrets.token_hex(8)
        recovery_salt = secrets.token_bytes(16)
        instance = cls(
            username=username,
            salt=salt.hex(),
            verifier=password_verifier(password, salt),
            vault=vault,
            wrapped_master=b64e(Cipher.encrypt(master, derive_key(password, salt, b"kek"))),
            recovery_salt=recovery_salt.hex(),
            recovery_blob=b64e(
                Cipher.encrypt(master, derive_key(recovery_code, recovery_salt, b"recovery"))
            ),
        )
        instance.save()
        return instance, recovery_code

    def change_password(self, new_password: str, master: bytes) -> None:
        salt = secrets.token_bytes(16)
        self.salt = salt.hex()
        self.verifier = password_verifier(new_password, salt)
        self.wrapped_master = b64e(Cipher.encrypt(master, derive_key(new_password, salt, b"kek")))
        self.save()

    def reset_password(self, recovery_code: str, new_password: str) -> None:
        master = Cipher.decrypt(
            b64d(self.recovery_blob), derive_key(recovery_code, self.recovery_salt_bytes, b"recovery")
        )
        self.change_password(new_password, master)

    def _entry_paths(self, name: str) -> tuple[Path, Path]:
        return self.vault / f"{name}{HEADER_SUFFIX}", self.vault / f"{name}{DATA_SUFFIX}"

    def _write_entry(self, name: str, data: bytes, master: bytes) -> tuple[Path, Path]:
        file_key = secrets.token_bytes(KEY_SIZE)
        header = {
            "version": 1,
            "file_size": len(data),
            "crypt_algo": "AES-256-CBC",
            "hash_algo": "SHA-256",
            "hash_value": hashlib.sha256(data).hexdigest(),
            "file_name": name,
            "crypt_key": b64e(file_key),
        }
        header_data = json.dumps(header, ensure_ascii=False).encode()
        encrypted_header = Cipher.encrypt(header_data, master)
        header_blob = MAGIC + struct.pack(">I", len(encrypted_header)) + encrypted_header
        header_path, data_path = self._entry_paths(name)
        header_path.write_bytes(header_blob)
        data_path.write_bytes(Cipher.encrypt(data, file_key))
        return header_path, data_path

    def _read_header(self, name: str, master: bytes) -> dict:
        header_path, _ = self._entry_paths(name)
        blob = header_path.read_bytes()
        if not blob.startswith(MAGIC):
            raise ValueError("not a vault header")
        offset = len(MAGIC)
        if len(blob) < offset + 4:
            raise ValueError("truncated vault header")
        (header_length,) = struct.unpack(">I", blob[offset : offset + 4])
        offset += 4
        if len(blob) != offset + header_length:
            raise ValueError("truncated vault header")
        header = json.loads(Cipher.decrypt(blob[offset:], master))
        if header.get("version") != 1:
            raise ValueError(f"unsupported vault version: {header.get('version')}")
        return header

    def _unpack_entry(self, name: str, master: bytes) -> tuple[dict, bytes]:
        header = self._read_header(name, master)
        _, data_path = self._entry_paths(name)
        data = Cipher.decrypt(data_path.read_bytes(), b64d(header["crypt_key"]))
        if len(data) != header["file_size"]:
            raise ValueError("size check failed")
        if hashlib.sha256(data).hexdigest() != header["hash_value"]:
            raise ValueError("hash check failed")
        return header, data

    def _check_name(self, filename: str) -> str:
        if not filename or Path(filename).name != filename:
            raise ValueError("invalid file name")
        header_path, data_path = self._entry_paths(filename)
        if not header_path.is_file() or not data_path.is_file():
            raise FileNotFoundError(filename)
        return filename

    def imp0rt(self, source: Path, master: bytes) -> tuple[Path, Path]:
        source = Path(source)
        if not source.is_file():
            raise FileNotFoundError(source)
        name = source.name
        paths = self._write_entry(name, source.read_bytes(), master)
        if name not in self.filelist:
            self.filelist.append(name)
        self.save()
        return paths

    def export(self, filename: str, target: Path, master: bytes) -> Path:
        header, data = self._unpack_entry(self._check_name(filename), master)
        target = Path(target)
        if target.is_dir():
            target = target / Path(header["file_name"]).name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def read(self, filename: str, master: bytes) -> bytes:
        return self._unpack_entry(self._check_name(filename), master)[1]

    def list_files(self, master: bytes) -> list[dict]:
        entries = []
        for header_path in sorted(self.vault.glob(f"*{HEADER_SUFFIX}")):
            if not header_path.is_file():
                continue
            name = header_path.name[: -len(HEADER_SUFFIX)]
            data_path = self._entry_paths(name)[1]
            entry = {
                "stored_name": name,
                "stored_size": header_path.stat().st_size
                + (data_path.stat().st_size if data_path.is_file() else 0),
            }
            try:
                header = self._read_header(name, master)
                entry.update(file_name=header["file_name"], file_size=header["file_size"])
            except Exception:
                entry.update(file_name=name, file_size=None)
            entries.append(entry)
        return entries


argument_parser = argparse.ArgumentParser(description="Vault launcher")
argument_parser.add_argument("--username", type=str, required=True, help="Username for the vault")
argument_parser.add_argument("--password", type=str, help="Password for the vault")
argument_parser.add_argument("--vault", type=str, help="Path to the vault directory")
argument_parser.add_argument("--salt", type=str, help="Salt for password hashing")
argument_parser.add_argument("--init", action="store_true", help="Initialize the vault")
argument_parser.add_argument("--reset", action="store_true", help="Reset the password with a recovery code")

MENU = """
Welcome to the Vault, Pesy Wu (3124004333)!

[1] Import a file
[2] Export a file
[3] Read a file
[4] List files
[5] Change password
[6] Reset password

[0] Exit
"""


def read_input(prompt: str) -> str:
    return input(prompt).strip()


def change_password(vault: Vault, master: bytes) -> None:
    new_password = read_input("New password: ")
    if not new_password:
        print("Password cannot be empty.")
        return
    if new_password != read_input("Confirm new password: "):
        print("Passwords do not match.")
        return
    vault.change_password(new_password, master)
    print("Password changed.")


def reset_password(vault: Vault) -> None:
    recovery_code = read_input("Recovery code: ")
    new_password = read_input("New password: ")
    if not new_password:
        print("Password cannot be empty.")
        return
    if new_password != read_input("Confirm new password: "):
        print("Passwords do not match.")
        return
    try:
        vault.reset_password(recovery_code, new_password)
    except Exception:
        print("Invalid recovery code.")
        return
    print("Password reset.")


def menu_loop(vault: Vault, master: bytes) -> None:
    while True:
        print(MENU)
        choice = read_input("Select an option: ")
        if choice == "1":
            raw = read_input("File to import: ")
            if not raw:
                continue
            try:
                header_path, data_path = vault.imp0rt(Path(raw), master)
            except (OSError, ValueError) as exc:
                print(f"Import failed: {exc}")
            else:
                print(f"Imported {Path(raw).name} -> {header_path.name}, {data_path.name}")
        elif choice == "2":
            filename = read_input("File in vault: ")
            target = read_input("Destination path: ")
            if not filename or not target:
                continue
            try:
                written = vault.export(filename, Path(target), master)
            except (OSError, ValueError, KeyError) as exc:
                print(f"Export failed: {exc}")
            else:
                print(f"Exported to {written}")
        elif choice == "3":
            filename = read_input("File in vault: ")
            if not filename:
                continue
            try:
                data = vault.read(filename, master)
            except (OSError, ValueError, KeyError) as exc:
                print(f"Read failed: {exc}")
                continue
            try:
                print(data.decode())
            except UnicodeDecodeError:
                print(f"[binary file, {len(data)} bytes]")
                print(data[:256].hex(" "))
        elif choice == "4":
            entries = vault.list_files(master)
            if not entries:
                print("Vault is empty.")
                continue
            print(f"{'Name':<32}{'Size':>12}{'Stored':>12}")
            for entry in entries:
                size = "-" if entry["file_size"] is None else str(entry["file_size"])
                print(f"{entry['file_name']:<32}{size:>12}{entry['stored_size']:>12}")
        elif choice == "5":
            change_password(vault, master)
        elif choice == "6":
            reset_password(vault)
        elif choice == "0":
            print("Bye.")
            return
        else:
            print("Unknown option.")


def main() -> None:
    args = argument_parser.parse_args()

    if args.init:
        if CONFIG_PATH.exists():
            print("config.json already exists; remove it before re-initializing.")
            sys.exit(1)
        if not args.vault:
            print("--vault is required with --init.")
            sys.exit(1)
        if not args.password:
            print("--password is required with --init.")
            sys.exit(1)
        salt = args.salt.encode() if args.salt else secrets.token_bytes(16)
        vault, recovery_code = Vault.create(args.username, args.password, Path(args.vault), salt)
        print(f"Vault initialized at {vault.vault}")
        print(f"Recovery code (save it, it is shown only once): {recovery_code}")
        menu_loop(vault, vault.unlock(args.password))
        return

    if not CONFIG_PATH.exists():
        print("Vault is not initialized. Run again with --init.")
        sys.exit(1)
    vault = Vault.load()

    if args.reset:
        if args.username != vault.username:
            print("Invalid username.")
            sys.exit(1)
        reset_password(vault)
        return

    if not vault.verify(args.username, args.password or ""):
        print("Invalid username or password.")
        sys.exit(1)

    master = vault.unlock(args.password)
    print(f"Vault accessed at {vault.vault}")
    menu_loop(vault, master)


if __name__ == "__main__":
    main()
