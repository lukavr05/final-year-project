import pandas as pd
import csv
import subprocess
from pathlib import Path
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import numpy as np

CSV_PATH = "../gcj2020.csv"                  
OUTPUT_SRC_DIR = Path("dataset/src")
OUTPUT_BIN_DIR = Path("dataset/bin")
NUM_FILES = 500
COMPILER = "g++"
COMP_FLAGS = ["-O2"]
NUM_WORKERS = cpu_count()

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
    
def compile_task(row_tuple):
    """Worker function for parallel compilation"""
    username, file_id, source_code, file_name = row_tuple
    
    # Filter non-C++ files
    if not file_name.lower().endswith(".cpp"):
        return {
            'file_id': file_id,
            'username': username,
            'status': 'skipped',
            'message': 'Not a C++ file'
        }
    
    # Create source directory and file
    out_dir = OUTPUT_SRC_DIR / username
    out_dir.mkdir(parents=True, exist_ok=True)
    src_path = out_dir / f"{file_id}.cpp"
    
    try:
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(source_code)
    except Exception as e:
        return {
            'file_id': file_id,
            'username': username,
            'status': 'error',
            'message': f'Write error: {str(e)}'
        }
    
    # Create binary directory
    bin_out_dir = OUTPUT_BIN_DIR / username
    bin_out_dir.mkdir(parents=True, exist_ok=True)
    bin_path = bin_out_dir / f"{file_id}.bin"
    
    # Compile
    try:
        cmd = [COMPILER, *COMP_FLAGS, "-o", str(bin_path), str(src_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        if result.returncode != 0:
            return {
                'file_id': file_id,
                'username': username,
                'status': 'failed',
                'message': result.stderr[:200]  # Truncate long errors
            }
        
        return {
            'file_id': file_id,
            'username': username,
            'status': 'success',
            'message': 'Compiled successfully'
        }
        
    except subprocess.TimeoutExpired:
        return {
            'file_id': file_id,
            'username': username,
            'status': 'timeout',
            'message': 'Compilation timeout (>20s)'
        }
    except Exception as e:
        return {
            'file_id': file_id,
            'username': username,
            'status': 'error',
            'message': str(e)
        }




def parseCSVnew():
    print(f"Reading CSV from {CSV_PATH}...")
    
    # Read CSV with pandas - much faster and more flexible
    df = pd.read_csv(CSV_PATH, nrows=NUM_FILES, encoding='utf-8')
    
    # Quick data validation
    required_cols = ['username', 'file', 'flines', 'full_path']
    missing_cols = set(required_cols) - set(df.columns)
    if missing_cols:
        raise ValueError(f"Missing required columns: {missing_cols}")
    
    print(f"Loaded {len(df)} files")
    
    # Filter C++ files upfront for efficiency
    df['is_cpp'] = df['full_path'].str.lower().str.endswith('.cpp')
    cpp_count = df['is_cpp'].sum()
    print(f"Found {cpp_count} C++ files out of {len(df)} total files")
    
    # Prepare data for parallel processing
    row_tuples = list(df[['username', 'file', 'flines', 'full_path']].itertuples(index=False, name=None))
    
    # Parallel compilation
    print(f"\nCompiling with {NUM_WORKERS} workers...")
    results = []
    
    with Pool(processes=NUM_WORKERS) as pool:
        for result in tqdm(pool.imap_unordered(compile_task, row_tuples), 
                          total=len(row_tuples), 
                          desc="Compiling"):
            results.append(result)
    
    # Convert results to DataFrame for easy analysis
    results_df = pd.DataFrame(results)
    
    # Generate statistics
    print("\n" + "="*60)
    print("COMPILATION SUMMARY")
    print("="*60)
    status_counts = results_df['status'].value_counts()
    print(status_counts.to_string())
    print(f"\nSuccess rate: {status_counts.get('success', 0) / len(results_df) * 100:.1f}%")
    
    # Save detailed logs
    print("\nSaving logs...")
    
    # Success log
    success_df = results_df[results_df['status'] == 'success']
    success_df[['username', 'file_id']].to_csv('compile_success.log', 
                                                index=False, 
                                                header=True)
    
    # Failure log with details
    fail_df = results_df[results_df['status'].isin(['failed', 'timeout', 'error'])]
    fail_df.to_csv('compile_fail.log', index=False, header=True)
    
    # Save comprehensive results
    results_df.to_csv('compile_results.csv', index=False)
    
    print(f"\n✓ Logs saved:")
    print(f"  - compile_success.log ({len(success_df)} files)")
    print(f"  - compile_fail.log ({len(fail_df)} files)")
    

def parseCSVold():
    print("Starting CSV Parsing & Compilation...")

    with open(CSV_PATH, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        success_count = 0

        for i, row in enumerate(tqdm(reader, total=NUM_FILES, desc="Files Read")):

            if i == NUM_FILES:
                break
        
            username = row['username']
            file_id = row['file']
            source_code = row['flines']
            file_name = row['full_path']

            out_dir = OUTPUT_SRC_DIR / username
            out_dir.mkdir(parents=True, exist_ok=True)

            if file_name.lower().endswith(".cpp"):
                src_path = out_dir / f"{file_id}.cpp"

                with open(src_path, "w", encoding="utf-8") as f:
                    f.write(source_code)

                bin_out_dir = OUTPUT_BIN_DIR / username
                bin_out_dir.mkdir(parents=True, exist_ok=True)
                bin_path = bin_out_dir / f"{file_id}.bin"

                if compile_source(src_path, bin_path):
                    success_count += 1
            else:
                fail_log.write(f"[SKIP] {file_name} not a C++ file\n")

        print(f"Successfully compiled {success_count} of {NUM_FILES} files.")

parseCSVnew()


success_log.close()
fail_log.close()
