"""Entry point for running the SecurePass desktop application."""

print("Launching SafeHaven Desktop App...")

from safehaven.app import SafeHavenApp


def main():
    """Create and run the desktop SecurePass application."""
    app = SecurePassApp()
    app.run()


if __name__ == "__main__":
    main()
