import os
import csv
import subprocess
from pathlib import Path

CSV_PATH = "../gcj2020.csv"                  
OUTPUT_SRC_DIR = Path("dataset/src")
OUTPUT_BIN_DIR = Path("dataset/bin")
COMPILER = "g++"
COMP_FLAGS = ["-O2"]

OUTPUT_SRC_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_BIN_DIR.mkdir(parents=True, exist_ok=True)

success_log = open("compile_success.log", "w")
fail_log = open("compile_fail.log", "w")

def compile_source(src_path: Path, bin_path: Path):
    try:
        cmd = [COMPILER, *COMP_FLAGS, "-o", str(bin_path), str(src_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)

        if result.returncode != 0:
            fail_log.write(f"[FAIL] {src_path} → {result.stderr}\n")
            return False

        success_log.write(f"[OK] {src_path}\n")
        return True

    except subprocess.TimeoutExpired:
        fail_log.write(f"[TIMEOUT] {src_path}\n")
        return False

print("Starting extraction + compilation...")

with open(CSV_PATH, newline='', encoding="utf-8") as csvfile:
    reader = csv.DictReader(csvfile)

    for i, row in enumerate(reader):
        print(f"{int((i / 50) * 100)}% complete", end="\r")
        if i == 50:
            print("\n")
            break
        username = row['username']
        file_id = row['file']
        source_code = row['flines']
        file_name = row['full_path']

        out_dir = OUTPUT_SRC_DIR / username
        out_dir.mkdir(parents=True, exist_ok=True)

        if file_name.lower().endswith(".cpp"):
            ext = ".cpp"
        else:
            ext = ".txt"  # default fallback

        src_path = out_dir / f"{file_id}{ext}"

        with open(src_path, "w", encoding="utf-8") as f:
            f.write(source_code)

        bin_out_dir = OUTPUT_BIN_DIR / username
        bin_out_dir.mkdir(parents=True, exist_ok=True)
        bin_path = bin_out_dir / f"{file_id}.bin"

        compile_source(src_path, bin_path)

print("Done.")
success_log.close()
fail_log.close()
