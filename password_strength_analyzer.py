import re
import hashlib
import math
from datetime import datetime

print("\n===================================")
print(" CYBERSECURITY PASSWORD ANALYZER ")
print("===================================\n")

# Common weak passwords
common_passwords = [
    "123456",
    "password",
    "admin",
    "qwerty",
    "abc123",
    "welcome",
    "12345678",
    "password123"
]

# Function to calculate entropy
def calculate_entropy(password):

    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26

    if re.search(r"[A-Z]", password):
        charset += 26

    if re.search(r"[0-9]", password):
        charset += 10

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset += 32

    if charset == 0:
        return 0

    entropy = len(password) * math.log2(charset)

    return round(entropy, 2)


# Function to analyze password
def analyze_password(password):

    score = 0
    feedback = []

    # Length Check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should contain at least 8 characters.")

    # Uppercase Check
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    # Lowercase Check
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    # Number Check
    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add at least one number.")

    # Special Character Check
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add at least one special character.")

    # Common Password Check
    if password.lower() in common_passwords:
        feedback.append("This is a commonly used weak password.")
        score = 1

    # Strength Level
    if score >= 6:
        strength = "VERY STRONG"
    elif score >= 5:
        strength = "STRONG"
    elif score >= 3:
        strength = "MEDIUM"
    else:
        strength = "WEAK"

    return strength, feedback


# User Input
password = input("Enter your password: ")

# Analyze Password
strength, suggestions = analyze_password(password)

# Entropy
entropy = calculate_entropy(password)

# SHA-256 Hashing
hashed_password = hashlib.sha256(password.encode()).hexdigest()

# Output Section
print("\n========== SECURITY REPORT ==========\n")

print(f"Password Strength : {strength}")
print(f"Password Entropy  : {entropy} bits")

print("\nSHA-256 Hash:")
print(hashed_password)

# Recommendations
if suggestions:
    print("\nSecurity Recommendations:")
    for item in suggestions:
        print("-", item)

# Cybersecurity Tips
print("\n===================================")
print(" Cybersecurity Tips")
print("===================================")

print("- Never reuse passwords.")
print("- Use multi-factor authentication.")
print("- Avoid common passwords.")
print("- Use long and unique passwords.")
print("- Change passwords regularly.")

# Save Report
report = f"""
========== PASSWORD SECURITY REPORT ==========
Generated On : {datetime.now()}

Password Strength : {strength}
Password Entropy  : {entropy} bits

SHA-256 Hash:
{hashed_password}

Recommendations:
"""

for item in suggestions:
    report += f"- {item}\n"

with open("security_report.txt", "w") as file:
    file.write(report)

print("\nSecurity report saved as 'security_report.txt'")
print("\n===================================\n")