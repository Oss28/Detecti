#!/usr/bin/env python3
import os
import subprocess

# Directory containing the .sol files
directory = './SCs_test/UEC/'

# Path to the Python program to run on each .sol file
program_path = 'Detecti.py'

other_args = ['-s', '1', '-a', 'a']

print("{:<23} {:<19} {}".format("", "True Positives", "False Positives"))

# Loop through the files in the directory
for filename in os.listdir(directory):
    if filename.endswith(".sol"):
        file_path = os.path.join(directory, filename)
        other_args = ['-s', '1', '-a', 'a']
        true_positives=0
        false_positives=0
        process = subprocess.Popen(['python3', program_path, file_path] + other_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        output_text = stdout.decode()
        
        # Look for "FINAL RESULTS" in the output
        start_index = output_text.rfind("FINAL RESULTS")
        if start_index != -1:
            # Extract the "FINAL RESULTS" section
            final_results_text = output_text[start_index:]
            #print(final_results_text)
            # Count True Positives and False Positives in the "FINAL RESULTS" section
            true_positives += final_results_text.count("True Positive")
            false_positives += final_results_text.count("False Positive")
        print("{:<30} {:<20} {}".format(filename, str(true_positives), str(false_positives)))

print()
directory = './SCs_test/TD/'
other_args = ['-s', '2', '-a', 'a']

# Loop through the files in the directory
for filename in os.listdir(directory):
    if filename.endswith(".sol"):
        file_path = os.path.join(directory, filename)
        true_positives=0
        false_positives=0
        process = subprocess.Popen(['python3', program_path, file_path] + other_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        output_text = stdout.decode()
        
        # Look for "FINAL RESULTS" in the output
        start_index = output_text.rfind("FINAL RESULTS")
        if start_index != -1:
            # Extract the "FINAL RESULTS" section
            final_results_text = output_text[start_index:]
            #print(final_results_text)
            # Count True Positives and False Positives in the "FINAL RESULTS" section
            true_positives += final_results_text.count("True Positive")
            false_positives += final_results_text.count("False Positive")
        print("{:<30} {:<20} {}".format(filename, str(true_positives), str(false_positives)))

print()
directory = './SCs_test/Ree/'
other_args = ['-s', '3', '-a', 'a']

# Loop through the files in the directory
for filename in os.listdir(directory):
    if filename.endswith(".sol"):
        file_path = os.path.join(directory, filename)
        true_positives=0
        false_positives=0
        process = subprocess.Popen(['python3', program_path, file_path] + other_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        output_text = stdout.decode()
        
        # Look for "FINAL RESULTS" in the output
        start_index = output_text.rfind("FINAL RESULTS")
        if start_index != -1:
            # Extract the "FINAL RESULTS" section
            final_results_text = output_text[start_index:]
            #print(final_results_text)
            # Count True Positives and False Positives in the "FINAL RESULTS" section
            true_positives += final_results_text.count("True Positive")
            false_positives += final_results_text.count("False Positive")
        print("{:<30} {:<20} {}".format(filename, str(true_positives), str(false_positives)))