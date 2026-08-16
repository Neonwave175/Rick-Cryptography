#!/bin/sh
brew install python3
python3 -m venv .chatvenv
source .chatvenv/bin/activate
pip install mlx
pip install numpy
pip install blake3
echo "Installed everything needed in .chatvenv"
echo "activate it with source .chatvenv/bin/activate"
echo "Or run this with 'rickchat.command' on macOS or 'bash rickchat.command' on linux"
echo "No direct run for windows LOL windows is too bad for devs"
