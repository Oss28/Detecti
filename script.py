#!/usr/bin/env python3

import os
import subprocess

vulnerability_map = {
    "URV": 1,  # Unchecked Return Value
    "TD": 2,   # Timestamp Dependence
    "REE": 3   # Reentrancy
}

dataset_dir = os.path.join(os.getcwd(), 'Dataset')

for vulnerability, s_value in vulnerability_map.items():
    vulnerability_dir = os.path.join(dataset_dir, vulnerability)
    if os.path.isdir(vulnerability_dir):
        for contract_file in os.listdir(vulnerability_dir):
            contract_path = os.path.join(vulnerability_dir, contract_file)
            if os.path.isfile(contract_path):
                command = ['./Detecti.py', '-s', str(s_value), '-a', 'a', contract_path]
                
                print(f"Running: {' '.join(command)}")
                result = subprocess.run(command, capture_output=True, text=True)
                
                print(result.stdout)
                if result.stderr:
                    print(f"Error: {result.stderr}")

    else:
        print(f"Directory {vulnerability_dir} does not exist.")
