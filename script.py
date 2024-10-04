#!/usr/bin/env python3

import os
import subprocess

# Mappa delle sottocartelle e i relativi parametri -s
vulnerability_map = {
    "URV": 1,  # Unchecked Return Value
    "TD": 2,   # Timestamp Dependence
    "REE": 3   # Reentrancy
}

# Percorso alla cartella Dataset
dataset_dir = os.path.join(os.getcwd(), 'Dataset')

# Itera su ogni sottocartella (una per ogni vulnerabilità)
for vulnerability, s_value in vulnerability_map.items():
    # Costruisci il percorso alla sottocartella
    vulnerability_dir = os.path.join(dataset_dir, vulnerability)

    # Assicurati che la cartella esista
    if os.path.isdir(vulnerability_dir):
        # Itera su ogni file di contratto all'interno della sottocartella
        for contract_file in os.listdir(vulnerability_dir):
            # Costruisci il percorso completo al file di contratto
            contract_path = os.path.join(vulnerability_dir, contract_file)
            
            # Assicurati che sia un file (evita eventuali sottocartelle)
            if os.path.isfile(contract_path):
                # Costruisci il comando per lanciare il tool con il parametro -s corretto
                command = ['./Detecti.py', '-s', str(s_value), '-a', 'a', contract_path]
                
                # Lancia il comando
                print(f"Running: {' '.join(command)}")
                result = subprocess.run(command, capture_output=True, text=True)
                
                # Stampa l'output del comando
                print(result.stdout)
                if result.stderr:
                    print(f"Error: {result.stderr}")

    else:
        print(f"Directory {vulnerability_dir} does not exist.")