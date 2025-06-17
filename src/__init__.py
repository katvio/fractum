def cli():
    """Main CLI entry point."""
    from src.cli import cli as _cli

    return _cli()


if __name__ == "__main__":
    cli()
