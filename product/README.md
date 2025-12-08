# Programming Usage Guide

To simplify the usage of the programming aspect, it will be outlined briefly here.

## Requirements

This project requires the following components to run as intended:

- The `uv` Python package manager
- The `gcc` compiler for Linux

## Usage

To run the dataset generator, the CSV file(not included in the repository for storage purposes) must be downloaded from [Kaggle](https://www.kaggle.com/datasets/jur1cek/gcj-dataset). For this project, the `gcj2020.csv` file is used.

Then, make sure to save the file in the `machine-learning/dataset-generation/` directory.

Then, in the `model` directory, you can run the following commands:

```bash
uv sync
uv run dataset-generator.py
```

This will compile all source code and generate a dataset. Logs of the operation can be found in `compile_fail.log` and `compile_success.log` for further analysis.