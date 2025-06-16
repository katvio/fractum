import json
from pathlib import Path

import click

from src.cli.commands import decrypt, encrypt, verify


def interactive_mode() -> None:
    """Interactive mode guiding the user step by step."""
    click.echo("\n=== Fractum Interactive Mode ===")

    # Mapping choices to functions
    operations = {
        1: ("Encrypt a file", interactive_encrypt),
        2: ("Decrypt a file", interactive_decrypt),
        3: ("Verify shares", interactive_verify),
        4: ("Quit", None),
    }

    while True:
        click.echo("\nWhat would you like to do?")
        for choice, (description, _) in operations.items():
            click.echo(f"{choice}. {description}")

        try:
            choice = click.prompt("Your choice", type=int)
            if choice not in operations:
                click.echo("Invalid choice. Please enter a number between 1 and 4.")
                continue

            if choice == 4:  # Quit
                click.echo("\nGoodbye!")
                break

            description, operation = operations[choice]
            click.echo(f"\n=== {description} ===")

            try:
                if operation is not None and operation():
                    click.echo("\nOperation completed successfully!")
            except Exception as e:
                click.echo(f"\nError: {str(e)}", err=True)

            if not click.confirm(
                "\nWould you like to perform another operation?", default=None
            ):
                click.echo("\nGoodbye!")
                break

        except ValueError:
            click.echo("Please enter a valid number.")
            continue


def interactive_encrypt() -> bool:
    """Interactive mode for encryption."""
    try:
        # Ask for file to encrypt
        input_file = click.prompt(
            "Full path of the file to encrypt",
            type=click.Path(exists=True, dir_okay=False, file_okay=True),
        )

        # Ask if using existing shares
        use_existing = click.confirm(
            "Do you want to use existing shares?", default=None
        )
        existing_shares = None
        if use_existing:
            existing_shares = click.prompt(
                "Full path of the directory containing existing shares",
                type=click.Path(exists=True, dir_okay=True, file_okay=False),
            )
            # Convert to absolute path
            existing_shares = str(Path(existing_shares).absolute())
            click.echo(f"Using existing shares from: {existing_shares}")

            # Check existing shares - examine all files, not just those with specific names
            share_files = []
            existing_shares_path = Path(existing_shares).absolute()

            # First try general pattern
            for file_path in existing_shares_path.glob("*.*"):
                if file_path.is_file():
                    try:
                        with open(file_path, "r") as f:
                            share_info = json.load(f)
                            # Check if this is a valid share file by looking for essential fields
                            if all(
                                key in share_info
                                for key in [
                                    "share_index",
                                    (
                                        "share_key"
                                        if "share_key" in share_info
                                        else "share"
                                    ),
                                    "label",
                                    "threshold",
                                    "total_shares",
                                ]
                            ):
                                share_files.append(file_path)
                    except (json.JSONDecodeError, UnicodeDecodeError, IOError):
                        # Not a valid JSON file, skip it
                        continue

            # If no files found with general pattern, try specific patterns
            if not share_files:
                click.echo(
                    "No shares found with standard naming. Trying alternative formats..."
                )
                for file_pattern in ["share_*.txt", "*.share", "*.json"]:
                    potential_files = list(existing_shares_path.glob(file_pattern))
                    if potential_files:
                        for file_path in potential_files:
                            try:
                                with open(file_path, "r") as f:
                                    share_info = json.load(f)
                                    if all(
                                        key in share_info
                                        for key in [
                                            "share_index",
                                            (
                                                "share_key"
                                                if "share_key" in share_info
                                                else "share"
                                            ),
                                            "label",
                                        ]
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

            # Read label from first share
            with open(share_files[0], "r") as f:
                share_info = json.load(f)
                existing_label = share_info["label"]

            click.echo(f"\nExisting shares found with label: {existing_label}")
            click.echo("You must use the same label for compatibility")
            label = existing_label
            click.echo(f"Label used: {label}")

            # Read parameters from existing shares
            threshold = share_info.get("threshold", 3)
            total_shares = share_info.get("total_shares", 5)
            click.echo("Existing shares parameters:")
            click.echo(f"- Threshold: {threshold}")
            click.echo(f"- Total shares: {total_shares}")

        else:
            # Ask for threshold
            threshold = click.prompt(
                "Minimum number of shares needed for decryption", type=int
            )
            while threshold < 2:
                click.echo("Threshold must be greater than 1")
                threshold = click.prompt(
                    "Minimum number of shares needed for decryption", type=int
                )

            # Ask for total shares
            total_shares = click.prompt("Total number of shares to generate", type=int)
            while total_shares < threshold:
                click.echo(
                    f"Total shares must be greater than or equal to threshold ({threshold})"
                )
                total_shares = click.prompt(
                    "Total number of shares to generate", type=int
                )

            # Ask for label
            label = click.prompt("Label to identify the shares")
            if not label:
                click.echo("Label cannot be empty")
                return False

        # Ask for verbose mode
        verbose = click.confirm("Do you want to enable verbose mode?", default=None)

        # Confirm parameters
        click.echo("\nEncryption parameters:")
        click.echo(f"File to encrypt: {input_file}")
        click.echo(f"Threshold: {threshold}")
        click.echo(f"Total shares: {total_shares}")
        click.echo(f"Label: {label}")
        click.echo(f"Existing shares: {'Yes' if use_existing else 'No'}")
        if use_existing:
            click.echo(f"Shares directory: {existing_shares}")
        click.echo(f"Verbose mode: {'Enabled' if verbose else 'Disabled'}")

        # Execute command via Click
        ctx = click.get_current_context()
        ctx.invoke(
            encrypt,
            input_file=input_file,
            threshold=threshold,
            shares=total_shares,
            label=label,
            existing_shares=existing_shares,
            verbose=verbose,
        )
        return True

    except Exception as e:
        click.echo(f"\nError during encryption: {str(e)}", err=True)
        return False


def interactive_decrypt() -> bool:
    """Interactive mode for decryption."""
    try:
        # Ask for file to decrypt
        input_file = click.prompt(
            "Full path of the file to decrypt",
            type=click.Path(exists=True, dir_okay=False, file_okay=True),
        )

        # Ask if using files or manual entry
        use_manual = click.confirm(
            "Do you want to enter the share keys manually? If not, you will be asked to provide the path to the folder containing the necessary share files?",
            default=None,
        )

        if use_manual:
            shares_dir = None
        else:
            # Ask for shares directory
            shares_dir = click.prompt(
                "Full path of the directory containing shares",
                type=click.Path(exists=True, dir_okay=True, file_okay=False),
            )
            # Convert to absolute path
            shares_dir = str(Path(shares_dir).absolute())
            click.echo(f"Using shares directory: {shares_dir}")

        # Ask for verbose mode
        verbose = click.confirm("Do you want to enable verbose mode?", default=None)

        # Confirm parameters
        click.echo("\nDecryption parameters:")
        click.echo(f"File to decrypt: {input_file}")
        if use_manual:
            click.echo("Share entry: Manual")
        else:
            click.echo(f"Shares directory: {shares_dir}")
        click.echo(f"Verbose mode: {'Enabled' if verbose else 'Disabled'}")

        # Execute command via Click
        ctx = click.get_current_context()
        ctx.invoke(
            decrypt,
            input_file=input_file,
            shares_dir=shares_dir,
            manual_shares=use_manual,
            verbose=verbose,
        )
        return True

    except Exception as e:
        click.echo(f"\nError during decryption: {str(e)}", err=True)
        return False


def interactive_verify() -> bool:
    """Interactive mode for verification."""
    try:
        # Ask for shares directory
        shares_dir = click.prompt(
            "Full path of the directory containing shares", type=click.Path(exists=True)
        )
        # Convert to absolute path
        shares_dir = str(Path(shares_dir).absolute())

        # Confirm parameters
        click.echo("\nVerification parameters:")
        click.echo(f"Shares directory: {shares_dir}")

        # Execute command via Click
        ctx = click.get_current_context()
        ctx.invoke(verify, shares_dir=shares_dir)
        return True

    except Exception as e:
        click.echo(f"\nError during verification: {str(e)}", err=True)
        return False
