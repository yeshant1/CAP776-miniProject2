import csv
import re
import bcrypt
import requests
import random
import string
import os
from getpass import getpass
from datetime import datetime

# File paths
USERS_FILE = 'regno.csv'
SEARCH_HISTORY_FILE = 'search_history.csv'

# Constants
MAX_LOGIN_ATTEMPTS = 5
API_KEY = 'YOUR_API_KEY_HERE'  # Replace with your actual API key

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

def generate_captcha():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def check_users_file():
    correct_headers = ['email', 'password', 'security_question', 'security_answer']
    
    if not os.path.exists(USERS_FILE):
        print(f"The file {USERS_FILE} does not exist. Creating it with correct headers.")
        with open(USERS_FILE, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(correct_headers)
        return True
    
    with open(USERS_FILE, 'r') as file:
        reader = csv.reader(file)
        headers = next(reader, None)
        
        if not headers:
            print(f"The file {USERS_FILE} is empty. Adding correct headers.")
            with open(USERS_FILE, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(correct_headers)
            return True
        
        if headers != correct_headers:
            print(f"The file {USERS_FILE} has incorrect headers. Correcting them.")
            rows = list(reader)  # Read the remaining rows
            with open(USERS_FILE, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(correct_headers)
                writer.writerows(rows)
            return True
        
        if sum(1 for row in reader) == 0:
            print(f"The file {USERS_FILE} contains no user data.")
            return True
    
    return True

def email_exists(email):
    with open(USERS_FILE, 'r') as file:
        reader = csv.DictReader(file)
        return any(row['email'] == email for row in reader)

def sign_up():
    print("Sign Up for a New Account")
    
    while True:
        email = input("Enter your email: ")
        if validate_email(email):
            if email_exists(email):
                print("This email is already registered. Please use a different email.")
            else:
                break
        else:
            print("Invalid email format. Please try again.")
    
    while True:
        password = getpass("Enter your password: ")
        if validate_password(password):
            confirm_password = getpass("Confirm your password: ")
            if password == confirm_password:
                break
            else:
                print("Passwords do not match. Please try again.")
        else:
            print("Invalid password. Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character.")
    
    security_question = input("Enter a security question: ")
    security_answer = input("Enter the answer to your security question: ")
    
    hashed_password = hash_password(password).decode('utf-8')
    
    with open(USERS_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([email, hashed_password, security_question, security_answer])
    
    print("Sign up successful! You can now log in with your new account.")

def login():
    attempts = 0
    while attempts < MAX_LOGIN_ATTEMPTS:
        email = input("Enter your email: ")
        password = getpass("Enter your password: ")
        
        captcha = generate_captcha()
        print(f"CAPTCHA: {captcha}")
        user_captcha = input("Enter the CAPTCHA: ")
        
        if user_captcha.upper() != captcha:
            print("Invalid CAPTCHA. Please try again.")
            continue
        
        with open(USERS_FILE, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row['email'] == email and verify_password(row['password'].encode('utf-8'), password):
                    print("Login successful!")
                    return row['email']
        
        attempts += 1
        print(f"Invalid credentials. {MAX_LOGIN_ATTEMPTS - attempts} attempts remaining.")
    
    print("Maximum login attempts exceeded. Application terminated.")
    return None

def forgot_password():
    email = input("Enter your registered email: ")
    found = False
    with open(USERS_FILE, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['email'] == email:
                found = True
                security_answer = input(f"Security Question: {row['security_question']}\nYour answer: ")
                if security_answer.lower() == row['security_answer'].lower():
                    while True:
                        new_password = getpass("Enter new password: ")
                        if validate_password(new_password):
                            update_password(email, new_password)
                            print("Password updated successfully.")
                            return
                        else:
                            print("Invalid password. Please try again.")
                else:
                    print("Incorrect security answer.")
                    return
    
    if not found:
        print(f"Email '{email}' not found in the system.")
        print("DEBUG: Emails in the system:")
        with open(USERS_FILE, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                print(f"- {row['email']}")

def update_password(email, new_password):
    rows = []
    with open(USERS_FILE, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['email'] == email:
                row['password'] = hash_password(new_password).decode('utf-8')
            rows.append(row)
    
    with open(USERS_FILE, 'w', newline='') as file:
        fieldnames = ['email', 'password', 'security_question', 'security_answer']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

def get_stock_data(symbol):
    url = f'https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol={symbol}&apikey={API_KEY}'
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        data = response.json()
        
        if 'Global Quote' not in data or not data['Global Quote']:
            print("No data found for the given symbol. Please verify and try again.")
            return None
        
        quote = data['Global Quote']
        return {
            'Symbol': quote['01. symbol'],
            'Current Price': quote['05. price'],
            'Open Price': quote['02. open'],
            'High Price': quote['03. high'],
            'Low Price': quote['04. low'],
            'Previous Close': quote['08. previous close'],
            'Volume': quote['06. volume']
        }
    except requests.RequestException as e:
        print(f"Error fetching stock data: {e}")
        print("Please check your internet connection and try again.")
        return None

def log_search(email, symbol):
    with open(SEARCH_HISTORY_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([email, symbol, datetime.now().strftime("%Y-%m-%d %H:%M:%S")])

def main():
    print("Welcome to the Stock Market Data Console Application")
    
    if not check_users_file():
        print("Error initializing user file. Please check file permissions and try again.")
        return
    
    while True:
        choice = input("1. Login\n2. Sign Up\n3. Forgot Password\n4. Exit\nEnter your choice: ")
        if choice == '1':
            email = login()
            if email:
                while True:
                    symbol = input("Enter the stock symbol (or 'q' to quit): ")
                    if symbol.lower() == 'q':
                        break
                    stock_data = get_stock_data(symbol)
                    if stock_data:
                        print("\nStock Data:")
                        for key, value in stock_data.items():
                            print(f"{key}: {value}")
                        log_search(email, symbol)
                    else:
                        print("Unable to retrieve stock data. Please check the symbol and try again.")
        elif choice == '2':
            sign_up()
        elif choice == '3':
            forgot_password()
        elif choice == '4':
            print("Thank you for using the Stock Market Data Console Application. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()