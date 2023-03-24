# Multi-Attack
This is a 3 in 1 password attacking tool with a hash generator plus pass list file.

#Attacks You can perform with Multi-Attack

Type the following command to see the list of available options:

python m-attack.py -h

This will display the list of available options that can be used with the script.

Depending on the type of attack you want to perform, you will need to provide different arguments to the script.

For example, to perform a Dictionary Attack, you will need to provide the password hash that you want to crack. Here is an example command for performing a Dictionary Attack:

python m-attack.py dictionary --password_hash <password_hash>

Replace "<password_hash>" with the hash of the password you want to crack.

You can also specify a dictionary file to use for the attack by using the "--dictionary" argument followed by the path to the dictionary file.

For a Brute-Force Attack, you will need to specify the number of characters to try in the attack using the "--numb_of_char" argument, and the type of characters to try using the "--type_of_characters" argument. Here is an example command for performing a Brute-Force Attack:

python m-attack.py brute_force --password_hash <password_hash> --numb_of_char <num_of_chars> --type_of_characters <char_type>

Replace "<num_of_chars>" with the number of characters you want to try, and "<char_type>" with the type of characters you want to try. The available character types are:

1: All characters (letters, digits, and punctuation)
2: Letters only
3: Letters and digits only
4: Letters and punctuation only
5: Digits and punctuation only
6: Digits only

For a Random Login Attack, you will need to specify the username to use for the attack using the "--username" argument, the path to the file containing the list of passwords to try using the "--password_list" argument, and the URL of the login page using the "--url" argument. Here is an example command for performing a Random Login Attack:

python m-attack.py random_login --username <username> --password_list <password_list_file> --url <login_url>

Replace "<username>" with the username to use, "<password_list_file>" with the path to the file containing the list of passwords to try, and "<login_url>" with the URL of the login page.

For an SSH Brute-Force Attack, you will need to specify the hostname and port of the SSH server you want to attack using the "--hostname" and "--port" arguments, the username to use for the attack using the "--username" argument, and the path to the file containing the list of passwords to try using the "--password_list" argument. Here is an example command for performing an SSH Brute-Force Attack:

python m-attack.py ssh_brute_force --hostname <hostname> --port <port> --username <username> --password_list <password_list_file>

Replace "<hostname>" with the hostname of the SSH server, "<port>" with the port number to use, "<username>" with the username to use, and "<password_list_file>" with the path to the file containing the list of passwords.
 
 #NOTE# use this tool responsible , as illegal hacking can land you in jail.
 
