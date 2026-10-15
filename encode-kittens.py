"""
This encodes all of the kitten pictures in data/kittens/ into
immutable caps in the catalog at data/root/

The corresponding Read Caps for each file are put in
data/root/kittens-anthology.txt
"""

import os
import shutil
import subprocess
from pathlib import Path

kittens = Path("data/kittens").absolute()
##collection = Path("data/root").absolute()
collection = Path("kitten-catalog").absolute()

print(f"Encoding kittens in {kittens} to {collection}")

caps = {}

for k in os.listdir(kittens):
    p = kittens / k
    # cargo run -- encrypt --catalog data/root path/to/kitten.jpeg
    args = [
        "cargo", "run", "--",
        "--catalog", collection,
        "encrypt", p,
    ]
    cap = subprocess.check_output(args)
    caps[k] = cap.strip().decode("utf8")

with Path("data/kittens-anthology.txt").open("w") as f:
    for k in sorted(caps.keys()):
        line = f"{caps[k]} {k}"
        print(line)
        f.write(line + "\n")

print("publishing")
shutil.rmtree("kitten-catalog-published")
subprocess.check_output([
    "./target/debug/mcap",
    "publish", collection, "kitten-catalog-published",
])


