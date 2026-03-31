import os
import subprocess
from pathlib import Path

kittens = Path("data/kittens").absolute()
collection = Path("data/root").absolute()

print(f"Encoding kittens in {kittens} to {collection}")

caps = {}

for k in os.listdir(kittens):
    p = kittens / k
    # cargo run -- encrypt --catalog data/root path/to/kitten.jpeg
    args = [
        "cargo", "run", "encrypt",
        "--catalog", collection,
        p
    ]
    cap = subprocess.check_output(args)
    caps[k] = cap.strip().decode("utf8")

for k in sorted(caps.keys()):
    print(f"{k:>30} {caps[k]}")
