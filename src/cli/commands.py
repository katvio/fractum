import os
import sys
import json
import base64
import hashlib
import shutil
import zipfile
import time
import click
from pathlib import Path
from typing import List, Tuple
from Crypto.Cipher import AES

from src.crypto.memory import SecureMemory
from src.crypto.encryption import FileEncryptor
from src.shares.manager import ShareManager
from src.shares.metadata import ShareMetadata
from src.shares.archiver import ShareArchiver
from src.utils.integrity import calculate_tool_integrity, get_enhanced_random_bytes

@click.command()
@click.argument('input_file', type=click.Path(exists=True, dir_okay=False, file_okay=True))
@click.option('--threshold', '-t', required=True, type=int, help='Minimum number of shares needed')
@click.option('--shares', '-n', required=True, type=int, help='Total number of shares to generate')
@click.option('--label', '-l', required=True, help='Label to identify shares')
@click.option('--existing-shares', '-e', type=click.Path(exists=True, dir_okay=True, file_okay=False), help='Directory containing existing shares')
@click.option('--verbose', '-v', is_flag=True, help='Verbose mode')
def encrypt(input_file: str, threshold: int, shares: int, label: str, existing_shares: str, verbose: bool):
    """Encrypts a file and generates shares."""
    try:
        # Replace spaces with underscores in label
        label = label.replace(' ', '_')
        if verbose:
            click.echo(f"Using label: {label} (spaces replaced with underscores)")
            
        # Check Python version
        if sys.version_info < (3, 8):
            raise ValueError("Python 3.8 or higher is required")
            
        # Create shares directory if it doesn't exist
        shares_dir = Path("shares")
        if not shares_dir.exists():
            shares_dir.mkdir()
            if verbose:
                click.echo("Created shares directory")
        elif verbose:
            click.echo("Using existing shares directory")
        
        # Calculate integrity hashes
        tool_integrity = calculate_tool_integrity()
        
        if existing_shares:
            # Convert existing_shares to absolute path if necessary
            existing_shares_path = Path(existing_shares).absolute()
            if verbose:
                click.echo(f"Looking for existing shares in: {existing_shares_path}")
                
            # Use existing shares - examine all files, not just those with specific names
            share_files = []
            for file_path in existing_shares_path.glob("*.*"):
                if file_path.is_file():
                    try:
                        with open(file_path, 'r') as f:
                            share_info = json.load(f)
                            # Check if this is a valid share file by looking for essential fields
                            if all(key in share_info for key in ['share_index', 'share_key' if 'share_key' in share_info else 'share', 'label', 'threshold', 'total_shares']):
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
                                with open(file_path, 'r') as f:
                                    share_info = json.load(f)
                                    if all(key in share_info for key in ['share_index', 'share_key' if 'share_key' in share_info else 'share', 'label']):
                                        share_files.append(file_path)
                            except:
                                continue
                
                if not share_files:
                    raise ValueError(f"No valid share files found in specified directory: {existing_shares}")
                
            if verbose:
                click.echo(f"Found {len(share_files)} valid share files")
                
            # Read label from first share
            with open(share_files[0], 'r') as f:
                share_info = json.load(f)
                existing_label = share_info['label']
                
            click.echo(f"\nExisting shares found with label: {existing_label}")
            click.echo("You must use the same label for compatibility")
            label = existing_label
            click.echo(f"Label used: {label}")
            
            # Read parameters from existing shares
            threshold = share_info.get('threshold', 3)
            total_shares = share_info.get('total_shares', 5)
            click.echo(f"Existing shares parameters:")
            click.echo(f"- Threshold: {threshold}")
            click.echo(f"- Total shares: {total_shares}")
            
            shares_data, metadata = ShareManager.load_shares(share_files)
            
            # Verify metadata compatibility
            if metadata.label != label:
                raise ValueError(f"Share label mismatch: expected {label}, found {metadata.label}")
            
            # Use original parameters from metadata
            threshold = metadata.threshold
            shares = metadata.total_shares
            
            if verbose:
                click.echo(f"Using existing shares with parameters: threshold={threshold}, total_shares={shares}")
            
            share_manager = ShareManager(threshold, shares)
            key = share_manager.combine_shares(shares_data)
            
            # Get existing share_set_id
            with open(share_files[0], 'r') as f:
                share_info = json.load(f)
                share_set_id = share_info.get('share_set_id', None)
            
            if verbose:
                click.echo(f"Using {len(shares_data)} existing shares with ID: {share_set_id}")
        else:
            # Generate new shares
            # Generate new key with enhanced entropy
            key = get_enhanced_random_bytes(32)
            
            # Generate a unique set identifier hash for this group of shares
            # Using enhanced entropy for share_set_id generation
            random_component = get_enhanced_random_bytes(16).hex()
            input_filename = Path(input_file).stem
            timestamp = str(time.time())
            share_set_id = hashlib.sha256((label + input_filename + timestamp + random_component).encode()).hexdigest()[:16]
            
            if verbose:
                click.echo(f"Generated share set ID: {share_set_id}")
            
            share_manager = ShareManager(threshold, shares)
            share_data = share_manager.generate_shares(key, label)
            
            # Create archive manager
            archiver = ShareArchiver()
            
            # Save shares and create archives
            share_files = []
            for idx, share in share_data:
                share_file = f"share_{idx}.txt"
                with open(share_file, 'w') as f:
                    json.dump({
                        'share_index': idx,
                        'share_key': base64.b64encode(share).decode(),
                        'label': label,
                        'share_integrity_hash': hashlib.sha256(share).hexdigest(),
                        'threshold': threshold,
                        'total_shares': shares,
                        'tool_integrity': tool_integrity,
                        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                        'share_set_id': share_set_id  # Add the share set ID to identify related shares
                    }, f, indent=2)
                share_files.append(share_file)
            
            if verbose:
                click.echo(f"Generated shares: {shares}")
        
        # File encryption
        output_file = f"{input_file}.enc"
        encryptor = FileEncryptor(key)
        
        # Add share_set_id to metadata before encryption
        metadata = {
            'version': share_manager.version,
            'timestamp': int(time.time()),
            'share_set_id': share_set_id if 'share_set_id' in locals() else None
        }
        
        # Calculate data hash
        with open(input_file, 'rb') as f:
            data = f.read()
        data_hash = hashlib.sha256(data).hexdigest()
        
        # Encrypt the file with metadata
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            # Write metadata
            encryptor._write_metadata(f_out, data_hash, metadata)
            
            # Read the input file
            data = f_in.read()
            
            # Encrypt the data
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            # Write encryption data
            f_out.write(cipher.nonce)
            f_out.write(tag)
            f_out.write(ciphertext)
        
        if verbose:
            click.echo(f"Encrypted file: {output_file}")
        
        # Create archives for each share
        if not existing_shares:
            for idx, share_file in enumerate(share_files, 1):
                archive_path = archiver.create_share_archive(share_file, output_file, idx, label)
                if verbose:
                    click.echo(f"Created archive: {Path(archive_path).absolute()}")
                
                # Remove temporary share file
                os.remove(share_file)
        
        # Secure cleanup
        SecureMemory.secure_clear(key)
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@click.command()
@click.argument('input_file', type=click.Path(exists=True, dir_okay=False, file_okay=True))
@click.option('--shares-dir', '-s', type=click.Path(exists=True, dir_okay=True, file_okay=False), help='Path to directory containing shares or ZIP archives')
@click.option('--manual-shares', '-m', is_flag=True, help='Manually enter share values instead of using files')
@click.option('--verbose', '-v', is_flag=True, help='Verbose mode')
def decrypt(input_file: str, shares_dir: str, manual_shares: bool, verbose: bool):
    """Decrypts a file using shares."""
    try:
        # If manual shares option is selected, collect shares interactively
        if manual_shares:
            if verbose:
                click.echo("Manual share entry mode activated")
            shares_data, metadata = collect_manual_shares()
            
            if not shares_data or len(shares_data) < 2:
                raise ValueError("Not enough valid shares provided. Minimum 2 shares required.")
            
            if verbose:
                click.echo(f"Collected {len(shares_data)} manual shares successfully")
                click.echo(f"Using shares with parameters: threshold={metadata['threshold']}, total_shares={metadata['total_shares']}")
                
            # Reconstruct key
            share_manager = ShareManager(metadata['threshold'], metadata['total_shares'])
            key = share_manager.combine_shares(shares_data)
            
            # Decrypt file
            output_file = input_file[:-4] if input_file.endswith('.enc') else input_file + '.dec'
            encryptor = FileEncryptor(key)
            encryptor.decrypt_file(input_file, output_file)
            
            # Get absolute path of the decrypted file
            output_path = Path(output_file).absolute()
            click.echo(f"File successfully decrypted: {output_path}")
            
            # Secure cleanup
            SecureMemory.secure_clear(key)
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
        with open(input_file, 'rb') as f:
            # Read metadata
            encryptor = FileEncryptor(SecureMemory.secure_bytes(32))
            metadata = encryptor._read_metadata(f)
            extracted_share_set_id = metadata.get('share_set_id')
            
            if verbose:
                if extracted_share_set_id:
                    click.echo(f"Found share set ID in metadata: {extracted_share_set_id}")
                else:
                    click.echo("No share set ID found in metadata")
        
        # Dictionary to store shares by set_id and label
        shares_by_set_id = {}
        shares_by_label = {}
        
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
            if file_path.is_file() and not file_path.suffix == '.zip':  # Skip ZIP files which we already handled
                try:
                    with open(file_path, 'r') as f:
                        share_info = json.load(f)
                        # Check if this is a valid share file by looking for essential fields
                        if all(key in share_info for key in ['share_index', 'share_key' if 'share_key' in share_info else 'share', 'label']):
                            content_share_files.append(file_path)
                except (json.JSONDecodeError, UnicodeDecodeError, IOError):
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
                click.echo(f"Found {len(share_files)} files in directory, but none match the expected share format")
                click.echo("Please ensure you're pointing to a directory containing valid share files or archives")
                return
        
        if verbose:
            click.echo(f"Processing {len(share_files)} share files/archives")
        
        # Process each file and group by set_id and label
        for share_file in share_files:
            if str(share_file).endswith('.zip'):
                # Extract archive to temporary directory
                temp_dir = Path(f"temp_share_{share_file.stem}")
                temp_dir.mkdir(exist_ok=True)
                
                try:
                    with zipfile.ZipFile(share_file, 'r') as zipf:
                        zipf.extractall(temp_dir)
                    
                    # Look for share file
                    share_files_in_zip = list(temp_dir.glob("share_*.txt"))
                    if not share_files_in_zip:
                        if verbose:
                            click.echo(f"No share file found in archive {share_file}")
                        continue
                    
                    share_file = share_files_in_zip[0]
                except Exception as e:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    if verbose:
                        click.echo(f"Error extracting archive {share_file}: {str(e)}")
                    continue
            
            try:
                with open(share_file, 'r') as f:
                    share_info = json.load(f)
                    label = share_info['label']
                    share_set_id = share_info.get('share_set_id', None)
                    
                    # If share has a set_id, store by set_id
                    if share_set_id:
                        if share_set_id not in shares_by_set_id:
                            # Look for version in different places to maintain compatibility with old files
                            version = None
                            if 'tool_integrity' in share_info and 'shares_tool_version' in share_info['tool_integrity']:
                                version = share_info['tool_integrity']['shares_tool_version']
                            elif 'shares_tool_version' in share_info:
                                version = share_info['shares_tool_version']
                            elif 'version' in share_info:
                                version = share_info['version']
                            else:
                                from src import VERSION
                                version = VERSION
                                
                            shares_by_set_id[share_set_id] = {
                                'shares': [],
                                'metadata': {
                                    'version': version,
                                    'label': label,
                                    'threshold': share_info.get('threshold', 3),
                                    'total_shares': share_info.get('total_shares', 5)
                                }
                            }
                        
                        # Support both 'share_key' (new) and 'share' (legacy) for backward compatibility
                        share_key = share_info.get('share_key', share_info.get('share'))
                        if not share_key:
                            raise ValueError(f"No share key found in {share_file}")
                        
                        shares_by_set_id[share_set_id]['shares'].append((
                            share_info['share_index'],
                            base64.b64decode(share_key)
                        ))
                    
                    # Also store by label for backward compatibility
                    if label not in shares_by_label:
                        # Look for version in different places to maintain compatibility with old files
                        version = None
                        if 'tool_integrity' in share_info and 'shares_tool_version' in share_info['tool_integrity']:
                            version = share_info['tool_integrity']['shares_tool_version']
                        elif 'shares_tool_version' in share_info:
                            version = share_info['shares_tool_version']
                        elif 'version' in share_info:
                            version = share_info['version']
                        else:
                            from src import VERSION
                            version = VERSION
                            
                        shares_by_label[label] = {
                            'shares': [],
                            'metadata': {
                                'version': version,
                                'label': label,
                                'threshold': share_info.get('threshold', 3),
                                'total_shares': share_info.get('total_shares', 5)
                            }
                        }
                    
                    # Support both 'share_key' (new) and 'share' (legacy) for backward compatibility
                    share_key = share_info.get('share_key', share_info.get('share'))
                    if not share_key:
                        if verbose:
                            click.echo(f"No share key found in {share_file}")
                        continue
                    
                    shares_by_label[label]['shares'].append((
                        share_info['share_index'],
                        base64.b64decode(share_key)
                    ))
            except Exception as e:
                if verbose:
                    click.echo(f"Error processing {share_file}: {str(e)}")
                continue
            
            # Clean up temporary directory if it was an archive
            if str(share_file).endswith('.zip'):
                shutil.rmtree(temp_dir, ignore_errors=True)
        
        if verbose:
            if shares_by_set_id:
                click.echo(f"\nFound shares with set IDs: {', '.join(shares_by_set_id.keys())}")
            click.echo(f"Found shares for {len(shares_by_label)} different labels")
            for label in shares_by_label:
                click.echo(f"  - {label}: {len(shares_by_label[label]['shares'])} shares (threshold: {shares_by_label[label]['metadata']['threshold']})")
        
        # First attempt to find shares by share_set_id extracted from metadata
        if extracted_share_set_id and extracted_share_set_id in shares_by_set_id:
            if verbose:
                click.echo(f"Using shares with set ID: {extracted_share_set_id}")
            share_data = shares_by_set_id[extracted_share_set_id]['shares']
            metadata = shares_by_set_id[extracted_share_set_id]['metadata']
        else:
            # If not found by share_set_id, try to find matching shares by label
            if verbose:
                if shares_by_set_id:
                    click.echo(f"Found shares with set IDs: {', '.join(shares_by_set_id.keys())}")
                click.echo(f"Found shares for {len(shares_by_label)} different labels")
                for label in shares_by_label:
                    click.echo(f"  - {label}: {len(shares_by_label[label]['shares'])} shares (threshold: {shares_by_label[label]['metadata']['threshold']})")
            
            # Try to find matching shares for the input file by label
            input_label = None
            for label in shares_by_label:
                if label in input_file:
                    input_label = label
                    break
            
            if input_label is None:
                # If no exact match, try all available labels until one works
                if shares_by_label:
                    # Try each label until one works
                    for label in shares_by_label:
                        try:
                            if verbose:
                                click.echo(f"Trying shares with label: {label}")
                            
                            share_data = shares_by_label[label]['shares']
                            metadata = shares_by_label[label]['metadata']
                            
                            # Try to reconstruct key
                            share_manager = ShareManager(metadata['threshold'], metadata['total_shares'])
                            key = share_manager.combine_shares(share_data)
                            
                            # Try to decrypt with this key
                            output_file = input_file[:-4] if input_file.endswith('.enc') else input_file + '.dec'
                            encryptor = FileEncryptor(key)
                            
                            # Try to decrypt a small portion of the file to verify the key
                            with open(input_file, 'rb') as f:
                                # Skip metadata
                                metadata_len = int.from_bytes(f.read(4), 'big')
                                f.read(metadata_len)
                                
                                # Read a small portion of the encrypted data
                                nonce = f.read(16)
                                tag = f.read(16)
                                ciphertext = f.read(32)  # Just read a small portion
                            
                            # Try to decrypt this small portion
                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                            try:
                                cipher.decrypt_and_verify(ciphertext, tag)
                                # If we get here, the key is correct
                                if verbose:
                                    click.echo(f"Successfully verified key with label: {label}")
                                break
                            except ValueError:
                                # Key is incorrect, try next label
                                if verbose:
                                    click.echo(f"Key verification failed for label: {label}")
                                continue
                        except Exception as e:
                            if verbose:
                                click.echo(f"Error trying label {label}: {str(e)}")
                            continue
                    else:
                        # If we get here, none of the labels worked
                        raise ValueError("No compatible shares found. None of the available shares could decrypt the file.")
                else:
                    raise ValueError("No compatible shares found")
            else:
                share_data = shares_by_label[input_label]['shares']
                metadata = shares_by_label[input_label]['metadata']
        
        if verbose:
            if 'label' in metadata:
                click.echo(f"\nUsing shares for label: {metadata['label']}")
            click.echo(f"Found {len(share_data)} shares (need {metadata['threshold']})")
        
        # Get scheme parameters from metadata
        threshold = metadata['threshold']
        total_shares = metadata['total_shares']
        
        # Reconstruct key
        share_manager = ShareManager(threshold, total_shares)
        key = share_manager.combine_shares(share_data)
        if verbose:
            click.echo("Key reconstructed from shares")
        
        # File decryption
        output_file = input_file[:-4] if input_file.endswith('.enc') else input_file + '.dec'
        encryptor = FileEncryptor(key)
        encryptor.decrypt_file(input_file, output_file)
        
        # Get absolute path of the decrypted file
        output_path = Path(output_file).absolute()
        click.echo(f"File successfully decrypted: {output_path}")
        
        # Secure cleanup
        SecureMemory.secure_clear(key)
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

def collect_manual_shares() -> Tuple[List[Tuple[int, bytes]], dict]:
    """Collects shares manually from user input."""
    click.echo("\n=== Manual Share Entry ===")
    click.echo("Enter share details when prompted. Enter 'done' when finished.")
    
    shares = []
    metadata = None
    
    while True:
        # Get share index
        share_index_input = click.prompt("Share index (or 'done' to finish)", type=str)
        if share_index_input.lower() == 'done':
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
                    
            except (ValueError, base64.binascii.Error):
                # If Base64 fails, try hex
                # Remove any whitespace or colons that might be in the hex string
                hex_value = share_value.replace(":", "").replace(" ", "")
                
                # Check if it looks like a hex string (only hex chars)
                if all(c in '0123456789abcdefABCDEF' for c in hex_value):
                    # Convert from hex to bytes
                    share_data = bytes.fromhex(hex_value)
                    
                    # Check length - should be 32 bytes
                    if len(share_data) != 32:
                        raise ValueError(f"Incorrect length for Hex data: {len(share_data)} bytes (expected 32)")
                else:
                    raise ValueError("Share key value must be valid Base64 or Hex")
                
        except Exception as e:
            click.echo(f"Invalid share key value: {str(e)}. Please try again.")
            continue
            
        # First share determines metadata
        if not metadata:
            threshold = click.prompt("Threshold (minimum number of shares needed)", type=int)
            total_shares = click.prompt("Total shares", type=int)
            
            if threshold < 2 or threshold > total_shares or total_shares > 255:
                click.echo("Invalid parameters. Threshold must be >= 2, total_shares must be >= threshold and <= 255.")
                continue
                
            from src import VERSION
            metadata = {
                'version': VERSION,
                'threshold': threshold,
                'total_shares': total_shares
            }
            
        # Add share to collection
        shares.append((share_index, share_data))
        click.echo(f"Share {share_index} added successfully. Total shares: {len(shares)}")
        
        # Check if we have enough shares
        if len(shares) >= metadata['threshold']:
            if click.confirm("You have enough shares for reconstruction. Proceed with decryption?", default=None):
                break
    
    # Final verification
    if len(shares) < 2:
        click.echo("Warning: Not enough shares provided. Minimum 2 shares required.")
        
    return shares, metadata

@click.command()
@click.option('--shares-dir', '-s', required=True, type=click.Path(exists=True), help='Path to directory containing shares or ZIP archives')
def verify(shares_dir: str):
    """Verifies share integrity."""
    try:
        shares_path = Path(shares_dir).absolute()
        
        # Check if it's an archive directory
        if shares_path.is_dir():
            # First look for ZIP archives
            share_files = list(shares_path.glob("*.zip"))
            
            # Then look for all potential share files by examining content
            content_share_files = []
            for file_path in shares_path.glob("*.*"):
                if file_path.is_file() and not file_path.suffix == '.zip':  # Skip ZIP files which we already handled
                    try:
                        with open(file_path, 'r') as f:
                            share_info = json.load(f)
                            # Check if this is a valid share file by looking for essential fields
                            if all(key in share_info for key in ['share_index', 'share_key' if 'share_key' in share_info else 'share', 'label']):
                                content_share_files.append(file_path)
                    except (json.JSONDecodeError, UnicodeDecodeError, IOError):
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
                    click.echo(f"Found {len(share_files)} files in directory, but none match the expected share format")
                    click.echo("Please ensure you're pointing to a directory containing valid share files or archives")
                    return
        else:
            # It's a single file (archive or share)
            share_files = [shares_path]
        
        # Process each file
        for share_file in share_files:
            if str(share_file).endswith('.zip'):
                # Extract archive to temporary directory
                temp_dir = Path(f"temp_share_{share_file.stem}")
                temp_dir.mkdir(exist_ok=True)
                
                try:
                    with zipfile.ZipFile(share_file, 'r') as zipf:
                        zipf.extractall(temp_dir)
                    
                    # Look for share file
                    share_files_in_zip = list(temp_dir.glob("share_*.txt"))
                    if not share_files_in_zip:
                        click.echo(f"No share file found in archive {share_file}", err=True)
                        continue
                    
                    share_file = share_files_in_zip[0]
                except Exception as e:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    click.echo(f"Error extracting archive {share_file}: {str(e)}", err=True)
                    continue
            
            try:
                with open(share_file, 'r') as f:
                    share_info = json.load(f)
                    share_data = base64.b64decode(share_info.get('share_key', share_info.get('share')))
                    computed_hash = hashlib.sha256(share_data).hexdigest()
                    
                    if computed_hash != share_info['share_integrity_hash']:
                        click.echo(f"Verification error for {share_file}", err=True)
                    else:
                        click.echo(f"Share {share_file} successfully verified")
            except json.JSONDecodeError:
                click.echo(f"Invalid JSON format in {share_file}", err=True)
            except KeyError as e:
                click.echo(f"Missing required field in {share_file}: {str(e)}", err=True)
            except Exception as e:
                click.echo(f"Error processing {share_file}: {str(e)}", err=True)
            
            # Clean up temporary directory if it was an archive
            if str(share_file).endswith('.zip'):
                shutil.rmtree(temp_dir, ignore_errors=True)
                    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)
