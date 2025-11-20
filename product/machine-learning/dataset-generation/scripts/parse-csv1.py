import csv

def parseCSV(path):
    with open(path, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)

        row = next(reader) # Only extracting the first row
        
        username = row['username']
        file_id = row['file']
        source_code = row['flines']
        file_name = row['full_path']

    print(f"Username: {username}\nFile ID: {file_id}\nFile Name: {file_name}\nSource Code: {source_code}")

parseCSV("../gcj2020.csv")   