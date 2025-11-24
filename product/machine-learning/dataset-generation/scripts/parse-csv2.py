import csv
import os
from pathlib import Path

def parseCSV(path):

    # The output directory
    OUTPUT_DIR =  Path("test/src")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(path, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)

        row = next(reader)

        username = row['username']
        file_id = row['file']
        source_code = row['flines']
        file_name = row['full_path']

        out_dir = OUTPUT_DIR / username
        out_dir.mkdir(parents=True, exist_ok=True)

        if file_name.lower().endswith(".cpp"):
            ext = ".cpp"
        else:
            ext = ".txt"

        new_file_name = file_id + ext
        src_path = out_dir / new_file_name

        with open(src_path, "w", encoding="utf-8") as f:
            f.write(source_code)
            
parseCSV("../gcj2020.csv")
