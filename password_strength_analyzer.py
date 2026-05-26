import re
import hashlib
import math
from datetime import datetime

print("\nPASSWORD SECURITY ANALYZER\n")

# List of commonly used weak passwords
weak_passwords = [
    "123456",
    "password",
    "admin",
    "qwerty",
    "abc123",
    "welcome"
]

# Function to calculate password entropy
def calculate_entropy(password):

    character_set = 0

    if re.search(r"[a-z]", password):
        character_set += 26

    if re.search(r"[A-Z]", password):
        character_set += 26

    if re.search(r"[0-9]", password):
        character_set += 10

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        character_set += 32

    if character_set == 0:
        return 0

    entropy = len(password) * math.log2(character_set)

    return round(entropy, 2)


# Function to analyze password strength
def check_password_strength(password):

    score = 0
    suggestions = []

    # Length validation
    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters.")

    # Uppercase validation
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add at least one uppercase letter.")

    # Lowercase validation
    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add at least one lowercase letter.")

    # Numeric validation
    if re.search(r"[0-9]", password):
        score += 1
    else:
        suggestions.append("Include at least one number.")

    # Special character validation
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        suggestions.append("Include at least one special character.")

    # Weak password detection
    if password.lower() in weak_passwords:
        suggestions.append("This password is commonly used and insecure.")
        score = 1

    # Password strength levels
    if score == 5:
        strength = "VERY STRONG"
    elif score == 4:
        strength = "STRONG"
    elif score == 3:
        strength = "MEDIUM"
    else:
        strength = "WEAK"

    return strength, suggestions


# User input
password = input("Enter a password to analyze: ")

# Analyze password
strength, feedback = check_password_strength(password)

# Entropy calculation
entropy = calculate_entropy(password)

# SHA-256 encryption
hashed_password = hashlib.sha256(password.encode()).hexdigest()

# Display report
print("\nSECURITY REPORT\n")

print(f"Password Strength : {strength}")
print(f"Password Entropy  : {entropy} bits")

print("\nEncrypted SHA-256 Hash:")
print(hashed_password)

# Display recommendations
if feedback:
    print("\nSecurity Suggestions:")
    for item in feedback:
        print(item)

# Cybersecurity awareness tips
print("\nCYBERSECURITY TIPS\n")

tips = [
    "Never reuse passwords.",
    "Use multi-factor authentication.",
    "Avoid predictable passwords.",
    "Use unique passwords for every account.",
    "Update passwords regularly."
]

for tip in tips:
    print(tip)

# Save report as text file
report = f"""
PASSWORD SECURITY REPORT
Generated Time : {datetime.now()}

Password Strength : {strength}
Password Entropy  : {entropy} bits

SHA-256 Hash:
{hashed_password}

Suggestions:
"""

for item in feedback:
    report += f"{item}\n"

with open("security_report.txt", "w") as file:
    file.write(report)

print("\nSecurity report saved successfully as 'security_report.txt'")
print("\nPassword security analysis completed.\n")
