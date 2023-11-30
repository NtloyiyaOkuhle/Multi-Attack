import random
import string

# Function to generate random PIN numbers
def generate_pin():
    return ''.join(random.choice(string.digits) for _ in range(random.randint(4, 8)))

# Function to generate word passwords
def generate_word_password():
    word_list = [
        "password", "admin", "login", "secret", "123456", "letmein", 
        "welcome", "monkey", "qwerty", "abc123"
    ]
    return random.choice(word_list)

# Function to generate random passwords with mixed characters
def generate_mixed_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(12))

# Generate 2000 passwords
passwords = set()
while len(passwords) < 2000:
    password_type = random.randint(1, 3)
    if password_type == 1:
        passwords.add(generate_pin())
    elif password_type == 2:
        passwords.add(generate_word_password())
    else:
        passwords.add(generate_mixed_password())

# Save passwords to a file
with open('2000_passwords.txt', 'w') as file:
    file.write('\n'.join(passwords))