Guideline for Using m-Attack.py

Disclaimer: This script is intended for educational purposes. Ensure you have proper authorization before using it. Unauthorized access and use may be illegal. Use responsibly.
1. Installation and Setup:

    Ensure you have Python installed on your system (version 3.6 or higher).
    Download or clone the m-Attack.py script to your local machine.

2. Prerequisites:

    Install the required Python libraries using the following command:

    bash

    pip install -r requirements.txt

3. Command-Line Interface (CLI) Usage:

    Run the script using the command line:

    bash

    python m-Attack.py <attack_type> [options]

4. Available Attack Types:

    Dictionary Attack
    Brute-Force Attack
    Random Login Attack
    SSH Brute-Force Attack

5. Command-Line Arguments:

    attack_type: Specify the type of attack you want to perform.

Examples:
1. Dictionary Attack:

    Usage:

    bash

python m-Attack.py dictionary --password_hash <hashed_password>

    Example:

    bash

        python m-Attack.py dictionary --password_hash 5f4dcc3b5aa765d61d8327deb882cf99

2. Brute-Force Attack:

    Usage:

    bash

python m-Attack.py brute_force --password_hash <hashed_password> --numb_of_char 8 --type_of_characters 1

    Example:

    bash

        python m-Attack.py brute_force --password_hash 5f4dcc3b5aa765d61d8327deb882cf99 --numb_of_char 8 --type_of_characters 1

3. Random Login Attack:

    Usage:

    bash

python m-Attack.py random_login --username <username> --password_list <passwords_file> --url <login_url>

    Example:

    bash

        python m-Attack.py random_login --username admin --password_list password_list.txt --url http://example.com/login

4. SSH Brute-Force Attack:

    Usage:

    bash

python m-Attack.py ssh_brute_force --hostname <hostname> --ssh_username <username> --ssh_password_list <ssh_passwords_file> --ssh_port 22

    Example:

    bash

        python m-Attack.py ssh_brute_force --hostname example.com --ssh_username root --ssh_password_list ssh_passwords.txt --ssh_port 22

6. Ethical Considerations:

    Before initiating any attack, the script displays an ethical warning.
    Confirm that you have proper authorization before proceeding.
    Only use this script for authorized penetration testing or educational purposes.

7. Analysis and Log Files:

    The script generates log files after each attack (dictionary_logs.txt, brute_force_logs.txt, random_login_logs.txt, ssh_brute_force_logs.txt).
    Use these log files for analysis using appropriate tools.

8. Responsible Use:

    Use this tool responsibly and only in controlled environments with proper authorization.
    Avoid unauthorized access to systems or networks.

9. Exit:

    After completing the attack, the script will exit automatically.

Always ensure you have explicit permission and legal authorization before performing any security-related activities or penetration testing. Prioritize ethical considerations and responsible use of this tool at all times.
