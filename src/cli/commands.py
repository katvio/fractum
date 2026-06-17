import base64
import binascii
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

import click

from Crypto.Cipher import AES
from src.crypto.encryption import FileEncryptor
from src.crypto.memory import SecureMemory
from src.shares.archiver import ShareArchiver
from src.shares.manager import ShareManager
from src.config import REQUIRED_PYTHON_VERSION, VERSION
from src.utils.integrity import calculate_tool_integrity, get_enhanced_random_bytes


@click.command()
@click.argument(
    "input_file", type=click.Path(exists=True, dir_okay=False, file_okay=True)
)
@click.option(
    "--threshold", "-t", required=True, type=int, help="Minimum number of shares needed"
)
@click.option(
    "--shares", "-n", required=True, type=int, help="Total number of shares to generate"
)
@click.option("--label", "-l", required=True, help="Label to identify shares")
@click.option(
    "--existing-shares",
    "-e",
    type=click.Path(exists=True, dir_okay=True, file_okay=False),
    help="Directory containing existing shares",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose mode")
@click.option(
    "--full-metadata",
    is_flag=True,
    default=False,
    help="Write label, total_shares and share_set_id to share files (less private, useful for debugging)",
)
def encrypt(
    input_file: str,
    threshold: int,
    shares: int,
    label: str,
    existing_shares: str,
    verbose: bool,
    full_metadata: bool,
) -> None:
    """Encrypts a file and generates shares."""
    key = None
    try:
        # Replace spaces with underscores in label
        label = label.replace(" ", "_")
        if verbose:
            click.echo(f"Using label: {label} (spaces replaced with underscores)")

        # Check Python version
        if sys.version_info < REQUIRED_PYTHON_VERSION:
            raise ValueError(
                f"Python {'.'.join(str(v) for v in REQUIRED_PYTHON_VERSION)} required, "
                f"got {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            )

        # Create shares directory if it doesn't exist
        shares_dir = Path("shares")
        if not shares_dir.exists():
            shares_dir.mkdir()
            if verbose:
                click.echo("Created shares directory")
        elif verbose:
            click.echo("Using existing shares directory")

        if existing_shares:
            # Convert existing_shares to absolute path if necessary
            existing_shares_path = Path(existing_shares).absolute()
            if verbose:
                click.echo(f"Looking for existing shares in: {existing_shares_path}")

            # Use existing shares - examine all files, not just those with specific names
            share_files: List[Path] = []
            for file_path in existing_shares_path.glob("*.*"):
                if file_path.is_file():
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            share_info = json.load(f)
                            # Check if this is a valid share file by looking for essential fields
                            if "share_index" in share_info and (
                                "share_key" in share_info or "share" in share_info
                            ):
                                share_files.append(file_path)
                    except (json.JSONDecodeError, UnicodeDecodeError, IOError):
                        # Not a valid JSON file, skip it
                        continue

            if not share_files:
                if verbose:
                    click.echo(f"No valid share files found in: {existing_shares_path}")
                    click.echo("Searching for share files in alternative formats...")

                # Try looking for share files with specific naming patterns
                for file_pattern in ["share_*.txt", "*.share", "*.json"]:
                    potential_files = list(existing_shares_path.glob(file_pattern))
                    if potential_files:
                        for file_path in potential_files:
                            try:
                                with open(file_path, "r", encoding="utf-8") as f:
                                    share_info = json.load(f)
                                    if "share_index" in share_info and (
                                        "share_key" in share_info or "share" in share_info
                                    ):
                                        share_files.append(file_path)
                            except (
                                json.JSONDecodeError,
                                UnicodeDecodeError,
                                IOError,
                            ) as e:
                                continue

                if not share_files:
                    raise ValueError(
                        f"No valid share files found in specified directory: {existing_shares}"
                    )

            if verbose:
                click.echo(f"Found {len(share_files)} valid share files")

            # Read label from first share (may be absent in minimal-metadata shares)
            with open(share_files[0], "r", encoding="utf-8") as f:
                share_info = json.load(f)
                existing_label = share_info.get("label")

            if existing_label:
                click.echo(f"\nExisting shares found with label: {existing_label}")
                click.echo("You must use the same label for compatibility")
                label = existing_label
                click.echo(f"Label used: {label}")
            else:
                click.echo("\nExisting shares found (no label — minimal metadata mode)")
                click.echo(f"Using provided label: {label}")

            # Read parameters from existing shares
            threshold = share_info.get("threshold", threshold)
            total_shares = share_info.get("total_shares", shares)
            click.echo("Existing shares parameters:")
            click.echo(f"- Threshold: {threshold}")
            click.echo(f"- Total shares: {total_shares}")

            share_files_str = [str(f) for f in share_files]
            shares_data, metadata = ShareManager.load_shares(share_files_str)

            # Verify metadata compatibility (only when label is present in both)
            if metadata.label and metadata.label != label:
                raise ValueError(
                    f"Share label mismatch: expected {label}, found {metadata.label}"
                )

            # Use original parameters from metadata
            threshold = metadata.threshold
            shares = metadata.total_shares or shares

            if verbose:
                click.echo(
                    f"Using existing shares with parameters: threshold={threshold}, total_shares={shares}"
                )

            share_manager = ShareManager(threshold, shares)
            key = bytearray(share_manager.combine_shares(shares_data))
            for _, share_bytes in shares_data:
                SecureMemory.secure_clear(bytearray(share_bytes))

            # Get existing share_set_id
            with open(share_files[0], "r", encoding="utf-8") as f:
                share_info = json.load(f)
                share_set_id = share_info.get("share_set_id", None)

            if verbose:
                click.echo(
                    f"Using {len(shares_data)} existing shares with ID: {share_set_id}"
                )
        else:
            # Generate new shares
            # Generate new key with enhanced entropy
            key = bytearray(get_enhanced_random_bytes(32))

            # Generate a unique set identifier hash for this group of shares
            # Using enhanced entropy for share_set_id generation
            random_component = get_enhanced_random_bytes(16).hex()
            input_filename = Path(input_file).stem
            timestamp = str(time.time())
            share_set_id = hashlib.sha256(
                (label + input_filename + timestamp + random_component).encode()
            ).hexdigest()[:16]

            if verbose:
                click.echo(f"Generated share set ID: {share_set_id}")

            share_manager = ShareManager(threshold, shares)
            share_data = share_manager.generate_shares(key, label)

            # Create archive manager
            archiver = ShareArchiver()

            # Save shares and create archives
            tool_integrity = calculate_tool_integrity() if full_metadata else None
            new_share_files: List[str] = []
            for idx, share in share_data:
                share_file = f"share_{idx}.txt"
                share_info_dict: Dict[str, Any] = {
                    "share_index": idx,
                    "share_key": base64.b64encode(share).decode(),
                    "threshold": threshold,
                    "hash": hashlib.sha256(share).hexdigest(),
                }
                if full_metadata:
                    share_info_dict.update({
                        "label": label,
                        "total_shares": shares,
                        "share_set_id": share_set_id,
                        "tool_integrity": tool_integrity,
                        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                    })
                with open(share_file, "w") as f:
                    json.dump(share_info_dict, f, indent=2)
                new_share_files.append(share_file)

            if verbose:
                click.echo(f"Generated shares: {shares}")

        # File encryption
        output_file = f"{input_file}.enc"
        encryptor = FileEncryptor(key)

        metadata_dict = {
            "share_set_id": share_set_id if "share_set_id" in locals() else None,
        }

        encryptor.encrypt_file(input_file, output_file, metadata_dict)

        if verbose:
            click.echo(f"Encrypted file: {output_file}")

        # Create archives for each share
        if not existing_shares:
            for idx, share_file in enumerate(new_share_files, 1):
                archive_path = archiver.create_share_archive(
                    share_file, output_file, idx, label
                )
                if verbose:
                    click.echo(f"Created archive: {Path(archive_path).absolute()}")

                # Remove temporary share file
                os.remove(share_file)

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)
    finally:
        if key is not None:
            SecureMemory.secure_clear(key)


def _extract_share_version(share_info: Dict[str, Any]) -> str:
    """Extract version from share_info, with fallback to current VERSION."""
    if "tool_integrity" in share_info and "shares_tool_version" in share_info.get("tool_integrity", {}):
        return share_info["tool_integrity"]["shares_tool_version"]
    if "shares_tool_version" in share_info:
        return share_info["shares_tool_version"]
    if "version" in share_info:
        return share_info["version"]
    return VERSION


@click.command()
@click.argument(
    "input_file", type=click.Path(exists=True, dir_okay=False, file_okay=True)
)
@click.option(
    "--shares-dir",
    "-s",
    type=click.Path(exists=True, dir_okay=True, file_okay=False),
    help="Path to directory containing shares or ZIP archives",
)
@click.option(
    "--manual-shares",
    "-m",
    is_flag=True,
    help="Manually enter share values instead of using files",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose mode")
def decrypt(
    input_file: str, shares_dir: str, manual_shares: bool, verbose: bool
) -> None:
    """Decrypts a file using shares."""
    try:
        # If manual shares option is selected, collect shares interactively
        if manual_shares:
            if verbose:
                click.echo("Manual share entry mode activated")
            shares_data, metadata = collect_manual_shares()

            if not shares_data or len(shares_data) < 2:
                raise ValueError(
                    "Not enough valid shares provided. Minimum 2 shares required."
                )

            if verbose:
                click.echo(f"Collected {len(shares_data)} manual shares successfully")
                click.echo(
                    f"Using shares with parameters: threshold={metadata['threshold']}, total_shares={metadata['total_shares']}"
                )

            # Reconstruct key and decrypt
            share_manager = ShareManager(
                metadata["threshold"], metadata["total_shares"]
            )
            with SecureMemory.secure_context(32) as key:
                key[:] = share_manager.combine_shares(shares_data)
                for _, share_bytes in shares_data:
                    SecureMemory.secure_clear(bytearray(share_bytes))

                # Decrypt file
                output_file = (
                    input_file[:-4] if input_file.endswith(".enc") else input_file + ".dec"
                )
                if Path(output_file).exists():
                    raise click.ClickException(
                        f"Output file already exists: {output_file}\n"
                        "Delete or rename it before decrypting."
                    )
                encryptor = FileEncryptor(key)
                encryptor.decrypt_file(input_file, output_file)

            output_path = Path(output_file).absolute()
            click.echo(f"File successfully decrypted: {output_path}")
            return

        # Original code for file-based shares
        if not shares_dir:
            raise ValueError("Either --shares-dir or --manual-shares must be provided")

        # Convert shares_dir to absolute path if it's a relative path
        shares_path = Path(shares_dir).absolute()

        if verbose:
            click.echo(f"Looking for shares in: {shares_path}")

        # Extract share_set_id from metadata
        extracted_share_set_id = None
        with open(input_file, "rb") as f:
            metadata = FileEncryptor._read_metadata(f)
            extracted_share_set_id = metadata.get("share_set_id")

            if verbose:
                if extracted_share_set_id:
                    click.echo(
                        f"Found share set ID in metadata: {extracted_share_set_id}"
                    )
                else:
                    click.echo("No share set ID found in metadata")

        # Dictionary to store shares by set_id and label
        shares_by_set_id: Dict[str, Dict[str, Any]] = {}
        shares_by_label: Dict[str, Dict[str, Any]] = {}

        # Look for share files in directory
        share_files = []

        # First try to find ZIP archives
        zip_files = list(shares_path.glob("*.zip"))
        if zip_files:
            share_files.extend(zip_files)
            if verbose:
                click.echo(f"Found {len(zip_files)} ZIP archives")

        # Then look for all potential share files by examining content
        content_share_files = []
        for file_path in shares_path.glob("*.*"):
            if (
                file_path.is_file() and not file_path.suffix == ".zip"
            ):  # Skip ZIP files which we already handled
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        share_info = json.load(f)
                        # Check if this is a valid share file by looking for essential fields
                        if "share_index" in share_info and (
                            "share_key" in share_info or "share" in share_info
                        ):
                            content_share_files.append(file_path)
                except (json.JSONDecodeError, UnicodeDecodeError, IOError) as e:
                    # Not a valid JSON file, skip it
                    continue

        # Add the content-detected share files
        if content_share_files:
            share_files.extend(content_share_files)

        if not share_files:
            # Try to find any file that might be a share
            all_files = list(shares_path.glob("*"))
            share_files = [f for f in all_files if f.is_file()]
            if not share_files:
                raise ValueError(f"No files found in directory {shares_path}")
            else:
                click.echo(
                    f"Found {len(share_files)} files in directory, but none match the expected share format"
                )
                click.echo(
                    "Please ensure you're pointing to a directory containing valid share files or archives"
                )
                return

        if verbose:
            click.echo(f"Processing {len(share_files)} share files/archives")

        # Process each file and group by set_id and label
        for share_file in share_files:
            temp_dir = None
            is_zip = str(share_file).endswith(".zip")
            if is_zip:
                # Extract archive to a secure temporary directory
                try:
                    temp_dir = Path(tempfile.mkdtemp(prefix="fractum_share_"))
                    with zipfile.ZipFile(share_file, "r") as zipf:
                        zipf.extractall(temp_dir)

                    # Look for share file
                    share_files_in_zip = list(temp_dir.glob("share_*.txt"))
                    if not share_files_in_zip:
                        if verbose:
                            click.echo(f"No share file found in archive {share_file}")
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        continue

                    share_file = share_files_in_zip[0]
                except Exception as e:
                    if temp_dir:
                        shutil.rmtree(temp_dir, ignore_errors=True)
                    if verbose:
                        click.echo(f"Error extracting archive: {str(e)}")
                    continue

            try:
                with open(share_file, "r", encoding="utf-8") as f:
                    share_info = json.load(f)
                    label = share_info.get("label", "_unlabeled")
                    share_set_id = share_info.get("share_set_id", None)

                    # Support both 'share_key' (new) and 'share' (legacy) for backward compatibility
                    share_key = share_info.get("share_key", share_info.get("share"))

                    if not share_key:
                        if verbose:
                            click.echo(f"No share key found in {share_file}")
                        continue

                    share_data = base64.b64decode(share_key)

                    # Hash integrity check — raises immediately (not swallowed) so the
                    # user knows exactly which share is corrupted.
                    expected_hash = share_info.get("hash")
                    if expected_hash:
                        computed = hashlib.sha256(share_data).hexdigest()
                        if computed != expected_hash:
                            raise ValueError(
                                f"Share {share_info.get('share_index', '?')} in {share_file} "
                                "is corrupted (hash mismatch). Contact the share holder."
                            )

                    # If share has a set_id, store by set_id
                    if share_set_id:
                        if share_set_id not in shares_by_set_id:
                            version = _extract_share_version(share_info)

                            shares_by_set_id[share_set_id] = {
                                "shares": [],
                                "metadata": {
                                    "version": version,
                                    "label": label,
                                    "threshold": share_info.get("threshold", 3),
                                    "total_shares": share_info.get("total_shares", 5),
                                },
                            }

                        shares_by_set_id[share_set_id]["shares"].append(
                            (share_info["share_index"], share_data)
                        )

                    # Also store by label for backward compatibility
                    if label not in shares_by_label:
                        version = _extract_share_version(share_info)

                        shares_by_label[label] = {
                            "shares": [],
                            "share_set_ids": [],  # parallel list — tracks set_id per share for N5 filtering
                            "metadata": {
                                "version": version,
                                "label": label,
                                "threshold": share_info.get("threshold", 3),
                                "total_shares": share_info.get("total_shares", 5),
                            },
                        }

                    shares_by_label[label]["shares"].append(
                        (share_info["share_index"], share_data)
                    )
                    shares_by_label[label]["share_set_ids"].append(share_set_id)
            except ValueError:
                # Validation errors (hash mismatch, missing key) must propagate so
                # the user gets an actionable message naming the corrupted share.
                raise
            except Exception as e:
                # Parse errors (bad JSON, encoding issues) → skip this file silently.
                if verbose:
                    click.echo(f"Error processing {share_file}: {str(e)}")
                continue

            # Clean up temporary directory if it was an archive
            if is_zip and temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

        if verbose:
            if shares_by_set_id:
                click.echo(
                    f"\nFound shares with set IDs: {', '.join(shares_by_set_id.keys())}"
                )
            click.echo(f"Found shares for {len(shares_by_label)} different labels")
            for label in shares_by_label:
                click.echo(
                    f"  - {label}: {len(shares_by_label[label]['shares'])} shares (threshold: {shares_by_label[label]['metadata']['threshold']})"
                )

        # First attempt to find shares by share_set_id extracted from metadata
        if extracted_share_set_id and extracted_share_set_id in shares_by_set_id:
            if verbose:
                click.echo(f"Using shares with set ID: {extracted_share_set_id}")
            share_data = shares_by_set_id[extracted_share_set_id]["shares"]
            metadata = shares_by_set_id[extracted_share_set_id]["metadata"]
        else:
            # If not found by share_set_id, try to find matching shares by label
            if verbose:
                if shares_by_set_id:
                    click.echo(
                        f"Found shares with set IDs: {', '.join(shares_by_set_id.keys())}"
                    )
                click.echo(f"Found shares for {len(shares_by_label)} different labels")
                for label in shares_by_label:
                    click.echo(
                        f"  - {label}: {len(shares_by_label[label]['shares'])} shares (threshold: {shares_by_label[label]['metadata']['threshold']})"
                    )

            # Try to find matching shares for the input file by label
            input_label = None
            for label in shares_by_label:
                if label in input_file:
                    input_label = label
                    break

            if input_label is None:
                # If no exact match, try all available labels until one works
                if shares_by_label:
                    for label in shares_by_label:
                        try:
                            if verbose:
                                click.echo(f"Trying shares with label: {label}")

                            all_shares = shares_by_label[label]["shares"]
                            set_ids = shares_by_label[label].get("share_set_ids", [])

                            # Filter by extracted_share_set_id to avoid mixing shares from different sets (N5)
                            if extracted_share_set_id and set_ids:
                                filtered = [
                                    s for s, sid in zip(all_shares, set_ids)
                                    if sid == extracted_share_set_id
                                ]
                                share_data = filtered if filtered else all_shares
                            else:
                                share_data = all_shares

                            metadata = shares_by_label[label]["metadata"]

                            share_manager = ShareManager(
                                metadata["threshold"], metadata["total_shares"]
                            )
                            key = bytearray(share_manager.combine_shares(share_data))
                            for _, share_bytes in share_data:
                                SecureMemory.secure_clear(bytearray(share_bytes))

                            # Verify key against the full ciphertext with correct AAD
                            with open(input_file, "rb") as f:
                                probe_meta_len = int.from_bytes(f.read(4), "big")
                                probe_meta_bytes = f.read(probe_meta_len)
                                nonce = f.read(16)
                                tag = f.read(16)
                                ciphertext = f.read()

                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                            cipher.update(probe_meta_bytes)
                            try:
                                cipher.decrypt_and_verify(ciphertext, tag)
                                if verbose:
                                    click.echo(
                                        f"Successfully verified key with label: {label}"
                                    )
                                break
                            except ValueError:
                                if verbose:
                                    click.echo(
                                        f"Key verification failed for label: {label}"
                                    )
                                SecureMemory.secure_clear(key)
                                continue
                        except Exception as e:
                            if verbose:
                                click.echo(f"Error trying label {label}: {str(e)}")
                            continue
                    else:
                        raise ValueError(
                            "No compatible shares found. None of the available shares could decrypt the file."
                        )
                else:
                    raise ValueError("No compatible shares found")
            else:
                share_data = shares_by_label[input_label]["shares"]
                metadata = shares_by_label[input_label]["metadata"]

        if verbose:
            if "label" in metadata:
                click.echo(f"\nUsing shares for label: {metadata['label']}")
            click.echo(f"Found {len(share_data)} shares (need {metadata['threshold']})")

        # Get scheme parameters from metadata
        threshold = metadata["threshold"]
        total_shares = metadata["total_shares"]

        # Reconstruct key
        share_manager = ShareManager(threshold, total_shares)
        with SecureMemory.secure_context(32) as key:
            key[:] = share_manager.combine_shares(share_data)
            for _, share_bytes in share_data:
                SecureMemory.secure_clear(bytearray(share_bytes))
            if verbose:
                click.echo("Key reconstructed from shares")

            # File decryption
            output_file = (
                input_file[:-4] if input_file.endswith(".enc") else input_file + ".dec"
            )
            if Path(output_file).exists():
                raise click.ClickException(
                    f"Output file already exists: {output_file}\n"
                    "Delete or rename it before decrypting."
                )
            encryptor = FileEncryptor(key)
            encryptor.decrypt_file(input_file, output_file)

        output_path = Path(output_file).absolute()
        click.echo(f"File successfully decrypted: {output_path}")

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


def collect_manual_shares() -> Tuple[List[Tuple[int, bytes]], Dict[str, Any]]:
    """Collects shares manually from user input."""
    click.echo("\n=== Manual Share Entry ===")
    
    # Get threshold and total shares first, at the beginning
    threshold = click.prompt(
        "Threshold (minimum number of shares needed)", type=int
    )
    total_shares = click.prompt("Total shares", type=int)

    if threshold < 2 or threshold > total_shares or total_shares > 255:
        raise ValueError(
            "Invalid parameters. Threshold must be >= 2, total_shares must be >= threshold and <= 255."
        )

    metadata = {
        "version": VERSION,
        "threshold": threshold,
        "total_shares": total_shares,
    }
    
    click.echo("\nEnter share details when prompted. Enter 'done' when finished.")

    shares = []

    while True:
        # Get share index
        share_index_input = click.prompt("Share index (or 'done' to finish)", type=str)
        if share_index_input.lower() == "done":
            break

        try:
            share_index = int(share_index_input)
            if share_index < 1 or share_index > 255:
                click.echo("Invalid share index. Must be between 1 and 255.")
                continue
        except ValueError:
            click.echo("Invalid share index. Please enter a number.")
            continue

        # Get share key value
        share_value = click.prompt("Share key value (Base64 or Hex encoded)", type=str)

        # Try to detect the format and decode accordingly
        try:
            # Try Base64 first
            try:
                share_data = base64.b64decode(share_value)

                # Verify this is actually valid Base64 by checking the length
                # The decoded data should be 32 bytes for our shares
                if len(share_data) != 32:
                    # Maybe it's hex encoded
                    raise ValueError("Incorrect data length for Base64")

            except (ValueError, binascii.Error):
                # If Base64 fails, try hex
                # Remove any whitespace or colons that might be in the hex string
                hex_value = share_value.replace(":", "").replace(" ", "")

                # Check if it looks like a hex string (only hex chars)
                if all(c in "0123456789abcdefABCDEF" for c in hex_value):
                    # Convert from hex to bytes
                    share_data = bytes.fromhex(hex_value)

                    # Check length - should be 32 bytes
                    if len(share_data) != 32:
                        raise ValueError(
                            f"Incorrect length for Hex data: {len(share_data)} bytes (expected 32)"
                        )
                else:
                    raise ValueError("Share key value must be valid Base64 or Hex")

        except Exception as e:
            click.echo(f"Invalid share key value: {str(e)}. Please try again.")
            continue

        # Add share to collection
        shares.append((share_index, share_data))
        click.echo(
            f"Share {share_index} added successfully. Total shares: {len(shares)}"
        )

        # Check if we have enough shares
        if len(shares) >= metadata["threshold"]:
            if click.confirm(
                "You have enough shares for reconstruction. Proceed with decryption?",
                default=None,
            ):
                break

    # Final verification
    if len(shares) < 2:
        click.echo("Warning: Not enough shares provided. Minimum 2 shares required.")

    # Ensure metadata is not None before returning
    if metadata is None:
        raise ValueError("No metadata collected")

    return shares, metadata
