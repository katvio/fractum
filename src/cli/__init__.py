import click
from src.cli.commands import encrypt, decrypt, verify
from src.cli.interactive import interactive_mode

@click.group(invoke_without_command=True)
@click.option('--version', is_flag=True, help='Show the version')
@click.option('--interactive', '-i', is_flag=True, help='Launch interactive mode')
@click.pass_context
def cli(ctx: click.Context, interactive: bool, version: bool) -> None:
    """Shamir's Secret Sharing Tool.

    A secure tool for file encryption and secret sharing using Shamir's Secret Sharing scheme.
    All operations can be performed offline using local packages.

    Available commands:

    encrypt:

        Encrypts a file and generates shares using Shamir's Secret Sharing.
        Creates ZIP archives containing shares and necessary files for decryption.

        Options:

            --threshold, -t
            Minimum number of shares needed to reconstruct the secret (must be > 1)

            --shares, -n
            Total number of shares to generate (must be >= threshold)

            --label, -l
            Label to identify the shares (used in filenames)

            --existing-shares, -e
            Directory containing existing shares to use for encryption
            (allows reusing shares from previous operations)

            --verbose, -v
            Enable verbose output for detailed operation information

    decrypt:

        Decrypts a file using the provided shares.
        Can use either individual share files or ZIP archives.

        Options:

            --shares-dir, -s
            Directory containing shares or ZIP archives
            (can contain a mix of .txt files and .zip archives)

            --manual-shares, -m
            Manually enter share values instead of using files
            (allows direct input of share index and share_key value in Base64 or Hex format)

            --verbose, -v
            Enable verbose output for detailed operation information

    verify:

        Verifies the integrity of shares and their compatibility.
        Checks both individual share files and ZIP archives.

        Options:

            --shares-dir, -s
            Directory containing shares or ZIP archives to verify
            (can be a single file or a directory)

    Global Options:

        --interactive, -i
        Launch the interactive mode that guides you through the operations step by step
        (a menu-driven interface that simplifies using the tool without command line arguments)

    Examples:

        # Launch interactive mode (recommended for new users)
        fractum -i

        # Encrypt a file with 3-5 scheme
        fractum encrypt secret.txt -t 3 -n 5 -l mysecret

        # Decrypt using shares from a directory
        fractum decrypt secret.txt.enc -s ./shares

        # Decrypt by manually entering share values
        fractum decrypt secret.txt.enc -m

        # Verify shares in a directory
        fractum verify -s ./shares
    """
    if version:
        # Import VERSION here to avoid circular import
        from src import VERSION
        click.echo(f"fractum version {VERSION}")
        ctx.exit()
        
    if ctx.invoked_subcommand is None:
        if interactive:
            interactive_mode()
        else:
            click.echo(ctx.get_help())
            ctx.exit()

# Register commands
cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(verify)
