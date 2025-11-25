import pandas as pd
import subprocess
from pathlib import Path
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed
from collections import defaultdict

CSV_PATH = "../gcj2020.csv"
OUTPUT_SRC_DIR = Path("dataset/src")
OUTPUT_BIN_DIR = Path("dataset/bin")
NUM_FILES = 500
CHUNK_SIZE = 100
COMPILER = "g++"
COMP_FLAGS = ["-O2"]
NUM_WORKERS = 8

OUTPUT_SRC_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_BIN_DIR.mkdir(parents=True, exist_ok=True)

def compile_source(src_path: Path, bin_path: Path):
    """Compile a single source file and return status."""

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

def process_file(args):
    """Process a single file: write source, compile, return result."""

    username, file_id, source_code, file_name, src_dir, bin_dir = args
    
    if not file_name.lower().endswith(".cpp"):
        return ("skip", username, file_id, "Not a C++ file")
    
    src_path = src_dir / f"{file_id}.cpp"
    try:
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(source_code)
    except Exception as e:
        return ("error", username, file_id, f"Write error: {str(e)[:100]}")
    
    bin_path = bin_dir / f"{file_id}.bin"
    ok = compile_source(src_path, bin_path)
    
    if ok:
        return ("success", username, file_id, None)
    else:
        return ("fail", username, file_id, None)

def precompute_directories():
    """Read CSV and precompute all unique user directories."""
    
    print("Precomputing directories...")
    unique_users = set()
    
    try:
        chunk_iter = pd.read_csv(CSV_PATH, chunksize=CHUNK_SIZE, dtype=str, engine="python", usecols=["username"])
        
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
    
    precompute_directories()
    
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
            futures = {executor.submit(process_file, task): task for task in tasks}
            
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
                        fail_log.write(f"[SKIP] {username}/{file_id} - {msg}\n")
                    
                    pbar.update(1)
        
        print(f"\nSuccessfully compiled {success_count} out of {len(tasks)} files. (Skipped: {skipped_count}, Failed: {failed_count})")
        
    finally:
        success_log.close()
        fail_log.close()

parseCSV()