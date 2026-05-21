"""Command-line module entrypoint.

Provides the `python -m bywaf` bridge to the CLI main function.

Used by:
- Python module execution: delegates directly to bywaf.app.main().
- packaging smoke tests: verifies the installed module entrypoint works."""


from .app import main


if __name__ == "__main__":
    raise SystemExit(main())
