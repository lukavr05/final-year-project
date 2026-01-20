import pandas as pd
import subprocess
import logging
import sys
from pathlib import Path
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed
from extraction_tool import *

CSV_PATH = "../gcj2020.csv"
OUTPUT_SRC_DIR = Path("dataset/src")
OUTPUT_BIN_DIR = Path("dataset/bin")
OUTPUT_DATA_DIR = Path("../../model")
OUTPUT_FILE = "binary-features.txt"

# Default values, can be overridden by command line arguments
NUM_FILES = 500
CHUNK_SIZE = 100
COMPILER = "g++"
COMP_FLAGS = ["-O2"]
NUM_WORKERS = 8
MIN_BINARIES = 5


def parse_args():
    global CSV_PATH

    if len(sys.argv) < 2:
        print("Usage: python dataset-generator2.py [num_files] [csv_path]")
        print("  num_files: Number of files to process (default: 500)")
        print("  csv_path: Path to CSV file (default: ../gcj2020.csv)")
        sys.exit(1)

    # Parse number of files
    try:
        num_files = int(sys.argv[1])
    except ValueError:
        print("Error: num_files must be an integer")
        sys.exit(1)

    # Parse CSV path if provided
    if len(sys.argv) > 2:
        CSV_PATH = sys.argv[2]

    return num_files


HEADER = [
    "jmp",
    "call",
    "ret",
    "cmp",
    "mov",
    "push",
    "pop",
    "add",
    "sub",
    "cfg_nodes",
    "cfg_edges",
    "density",
    "cyclomatic",
    "num_functions",
    "num_branches",
    "branch_ratio",
    "label",
]

OUTPUT_SRC_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_BIN_DIR.mkdir(parents=True, exist_ok=True)


def compileSourceCode(src_path: Path, bin_path: Path):
    try:
        result = subprocess.run(
            [COMPILER, *COMP_FLAGS, "-o", str(bin_path), str(src_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def processFile(args):
    username, file_id, source_code, file_name, src_dir, bin_dir = args

    if not file_name.lower().endswith(".cpp"):
        return ("skip", username, file_id, "INVALID FILE FORMAT")

    src_path = src_dir / f"{file_id}.cpp"
    try:
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(source_code)
    except Exception as e:
        return ("error", username, file_id, f"Write error: {str(e)[:100]}")

    bin_path = bin_dir / f"{file_id}.bin"
    ok = compileSourceCode(src_path, bin_path)

    if ok:
        return ("success", username, file_id, None)
    else:
        return ("fail", username, file_id, None)


def precomputeDirectories():
    """Read CSV and precompute all unique user directories."""

    print("Precomputing directories...")
    unique_users = set()

    try:
        chunk_iter = pd.read_csv(
            CSV_PATH,
            chunksize=CHUNK_SIZE,
            dtype=str,
            engine="python",
            usecols=["username"],
        )

        count = 0
        for chunk in chunk_iter:
            if count >= NUM_FILES:
                break
            for username in chunk["username"]:
                if count >= NUM_FILES:
                    break
                unique_users.add(username)
                count += 1

    except Exception as e:
        print(f"Warning: Could not precompute from username column: {e}")
        print("Will create directories on-the-fly instead.")
        return

    print(f"Creating directories for {len(unique_users)} users...")
    for username in tqdm(unique_users, desc="Progress", unit="user"):
        (OUTPUT_SRC_DIR / username).mkdir(parents=True, exist_ok=True)
        (OUTPUT_BIN_DIR / username).mkdir(parents=True, exist_ok=True)

    print(f"Precomputed {len(unique_users)} user directories")


def parseCSV():
    print("Starting CSV processing...")

    precomputeDirectories()

    tasks = []
    processed = 0

    print("Loading tasks...")
    chunk_iter = pd.read_csv(CSV_PATH, chunksize=CHUNK_SIZE, dtype=str, engine="python")

    for chunk in chunk_iter:
        if processed >= NUM_FILES:
            break

        for _, row in chunk.iterrows():
            if processed >= NUM_FILES:
                break

            username = row.get("username", "unknown")
            file_id = row.get("file", "unknown")
            source_code = row.get("flines", "")
            file_name = row.get("full_path", "")

            src_dir = OUTPUT_SRC_DIR / username
            bin_dir = OUTPUT_BIN_DIR / username

            tasks.append((username, file_id, source_code, file_name, src_dir, bin_dir))
            processed += 1

    print(f"Loaded {len(tasks)} tasks, starting parallel compilation...")

    success_count = 0
    failed_count = 0
    skipped_count = 0

    success_log = open("compile_success.log", "w", buffering=8192)
    fail_log = open("compile_fail.log", "w", buffering=8192)

    try:
        with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
            futures = {executor.submit(processFile, task): task for task in tasks}

            with tqdm(total=len(tasks), desc="Compiling", unit="file") as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    status, username, file_id, msg = result

                    if status == "success":
                        success_count += 1
                        success_log.write(f"[OK] {username}/{file_id}.cpp\n")

                    elif status == "fail" or status == "error":
                        failed_count += 1
                        fail_log.write(f"[FAILED] {username}/{file_id}.cpp\n")

                    elif status == "skip":
                        skipped_count += 1
                        fail_log.write(f"[SKIP] {username}/{file_name} - {msg}\n")

                    pbar.update(1)

        print(
            f"\nSuccessfully compiled {success_count} out of {len(tasks)} files. (Skipped: {skipped_count}, Failed: {failed_count})"
        )

    finally:
        success_log.close()
        fail_log.close()


def build_dataset():
    # Removing some unnecessary logs generated by the angr library (no impact)
    logging.getLogger("cle.loader").setLevel(logging.ERROR)
    parseCSV()
    print("Beginning dataset assembly...")
    users = sorted([d.name for d in OUTPUT_BIN_DIR.iterdir() if d.is_dir()])
    user_to_label = {user: i for i, user in enumerate(users)}
    valid_users = []
    for user in users:
        bin_count = sum(
            1 for f in (OUTPUT_BIN_DIR / user).iterdir() if f.name.endswith(".bin")
        )
        if bin_count >= MIN_BINARIES:
            valid_users.append(user)

    with open(OUTPUT_DATA_DIR / OUTPUT_FILE, "w") as f:
        print("Extracting features from binary files...")
        f.write(",".join(HEADER) + "\n")

        print(
            f"Found {len(valid_users)} valid users with at least {MIN_BINARIES} files."
        )
        for user in tqdm(
            valid_users, total=len(valid_users), desc="Processing", unit="file"
        ):
            user_dir = OUTPUT_BIN_DIR / user
            label = user_to_label[user]

            for bin_file in user_dir.iterdir():
                if not bin_file.name.endswith(".bin"):
                    continue

                try:
                    features = extractBinaryFeatures(str(bin_file))
                except Exception as e:
                    print(f"[WARN] Failed to extract from {bin_file}: {e}")
                    continue

                full_row = np.append(features, label)

                row_str = ",".join(str(v) for v in full_row)

                f.write(row_str + "\n")

    print(f"\nDataset written to {OUTPUT_FILE}")


if __name__ == "__main__":
    NUM_FILES = parse_args()
    print(f"Processing {NUM_FILES} files from {CSV_PATH}")
    build_dataset()
