import json
import time
from typing import Any, Dict, Optional, Union

from Crypto.Cipher import AES
from src.config import VERSION


class FileEncryptor:
    def __init__(self, key: Union[bytes, bytearray]):
        self.key = key
        self.version = VERSION

    @staticmethod
    def _read_metadata(f: Any) -> Dict[str, Any]:
        """Reads and parses metadata from an open .enc file (used for share_set_id routing)."""
        try:
            metadata_len = int.from_bytes(f.read(4), "big")
            metadata_bytes = f.read(metadata_len)
        except (OSError, IOError) as e:
            raise ValueError(f"Cannot read .enc header: {e}")

        try:
            metadata: Dict[str, Any] = json.loads(metadata_bytes.decode("utf-8"))
        except UnicodeDecodeError:
            try:
                metadata = json.loads(
                    metadata_bytes.decode("latin-1", errors="replace")
                )
            except json.JSONDecodeError:
                return {"version": VERSION}
        except json.JSONDecodeError:
            return {"version": VERSION}

        if "version" not in metadata:
            metadata["version"] = VERSION

        return metadata

    @staticmethod
    def _parse_version(version_str: Any) -> Optional[tuple]:
        try:
            return tuple(int(part) for part in str(version_str).split("."))
        except (ValueError, AttributeError):
            return None

    def _is_newer_version(self, file_version: Any) -> bool:
        """True only if file_version is a strictly newer, parseable version than this build.

        The .enc binary layout (length-prefixed metadata + nonce + tag + ciphertext) has been
        stable across 1.0.0-1.4.0, so older/equal versions remain decryptable — only a file
        from a future version this build doesn't understand is rejected.
        """
        current = self._parse_version(self.version)
        incoming = self._parse_version(file_version)
        if current is None or incoming is None:
            return False
        return incoming > current

    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Encrypts a file with AES-256-GCM. Metadata is bound to the ciphertext via AAD."""
        try:
            with open(input_path, "rb") as f:
                data = f.read()

            if metadata is None:
                metadata = {}
            metadata.update(
                {
                    "version": self.version,
                    "timestamp": int(time.time()),
                }
            )

            metadata_bytes = json.dumps(metadata, ensure_ascii=False).encode("utf-8")

            # Finalize metadata before creating cipher — metadata_bytes are the AAD
            cipher = AES.new(self.key, AES.MODE_GCM)
            cipher.update(metadata_bytes)
            ciphertext, tag = cipher.encrypt_and_digest(data)

            with open(output_path, "wb") as f:
                f.write(len(metadata_bytes).to_bytes(4, "big"))
                f.write(metadata_bytes)
                f.write(cipher.nonce)
                f.write(tag)
                f.write(ciphertext)
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Decrypts a file with AES-256-GCM, verifying metadata integrity via AAD."""
        try:
            with open(input_path, "rb") as f:
                header = f.read(4)
                if len(header) < 4:
                    raise ValueError("Truncated .enc file — header incomplete")
                metadata_len = int.from_bytes(header, "big")
                if metadata_len > 65536:
                    raise ValueError("Metadata length too large — suspect file")

                metadata_bytes = f.read(metadata_len)
                if len(metadata_bytes) < metadata_len:
                    raise ValueError("Truncated .enc file — metadata incomplete")

                try:
                    metadata = json.loads(metadata_bytes.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    raise ValueError(f"Corrupt metadata — json parse error: {e}")

                file_version = metadata.get("version", self.version)
                if self._is_newer_version(file_version):
                    raise ValueError(
                        f"Incompatible version: file was encrypted with Fractum {file_version}, "
                        f"which is newer than this build ({self.version}) — please upgrade Fractum"
                    )

                nonce = f.read(16)
                if len(nonce) != 16:
                    raise ValueError("Invalid or missing nonce")

                tag = f.read(16)
                if len(tag) != 16:
                    raise ValueError("Invalid or missing authentication tag")

                ciphertext = f.read()
                if not ciphertext:
                    raise ValueError("No encrypted data found")

            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            cipher.update(metadata_bytes)
            data = cipher.decrypt_and_verify(ciphertext, tag)

            if len(data) == 0:
                raise ValueError("Decrypted data is empty")

            with open(output_path, "wb") as f:
                f.write(data)

        except (ValueError, IOError) as e:
            raise ValueError(f"Decryption failed: {str(e)}")
        except Exception as e:
            raise ValueError(f"Unexpected error during decryption: {str(e)}")
