#!/usr/bin/env python3
"""Helper module for complex test skill."""

def greet(name: str) -> str:
    """Return a greeting message."""
    return f"Hello, {name}! Welcome to the complex test skill."

if __name__ == "__main__":
    print(greet("World"))
