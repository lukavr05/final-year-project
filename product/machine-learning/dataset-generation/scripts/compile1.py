import os
import csv
import subprocess
from pathlib import Path

SOURCE_DIR = Path("test/src/Benq/0000000000210bf5.cpp")
OUTPUT_DIR = Path("test/bin/Benq/")


OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def compileSourceCode(src_path, bin_path):
    try:
        cmd = ["g++", "-o", str(bin_path), str(src_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)

        if result.returncode != 0:
            print(f"FAILED: at {src_path}\nERROR: {result.stderr}\n")

        else:
            print("SUCCESS")
    
    except subprocess.TimeoutExpired:
        print("FAILED: Timed out")

compileSourceCode(SOURCE_DIR, OUTPUT_DIR)