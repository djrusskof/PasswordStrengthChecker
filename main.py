import tkinter as tk
from PIL import Image, ImageTk
import re
import ctypes

# Function to save password in clipboard
def buttonValidatePassword_click():
    print(f"{entryPassword.get()}")

# Function called when password entry text change
def entryPassword_change(*args):
    password = var.get()
    strength = calculatePasswordStrength(password)
    labelStrength.config(text=f"Password Strength: {strength}")
    update_strength_image(strength)

# Function to give a score to current typed password
def calculatePasswordStrength(password):
    length_criteria = len(password) >= 8
    uppercase_criteria = any(char.isupper() for char in password)
    lowercase_criteria = any(char.islower() for char in password)
    digit_criteria = any(char.isdigit() for char in password)
    special_char_criteria = any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for char in password)
    no_repeated_chars = len(set(password)) > len(password) * 0.7  # Less than 30% repeated characters
    no_sequences = not re.search(r'(.)\1{2,}', password)  # No sequences of 3 or more repeated characters

    strength_score = sum([
        length_criteria,
        uppercase_criteria,
        lowercase_criteria,
        digit_criteria,
        special_char_criteria,
        no_repeated_chars,
        no_sequences
    ])

    if strength_score == 7:
        return "Very Strong"
    elif strength_score == 6:
        return "Strong"
    elif strength_score == 5:
        return "Medium"
    elif strength_score == 4:
        return "Weak"
    else:
        return "Very Weak"

# Function to update image following password strngth score
def update_strength_image(strength):
    if strength == "Very Strong":
        img = img_very_strong
    elif strength == "Strong":
        img = img_strong
    elif strength == "Medium":
        img = img_medium
    elif strength == "Weak":
        img = img_weak
    else:
        img = img_very_weak
    labelImage.config(image=img)

# Function to resize image to fit desired size
def load_and_resize_image(path, size):
    image = Image.open(path)
    image = image.resize(size)
    return ImageTk.PhotoImage(image)


# Create the main window
root = tk.Tk()
root.iconbitmap("images/PasswordStrengthChecker.ico")
root.title("PSC - Password Strength Checker")
root.resizable(False, False)
root.geometry("350x280")

myappid = u'djrusskof.passwordStrengthChecker.1.0.0'
ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

# Desired image size
image_size = (241, 141)

# Load images for different password strengths
img_very_strong = load_and_resize_image("images/password_strength_very_strong.png", image_size)
img_strong = load_and_resize_image("images/password_strength_strong.png", image_size)
img_medium = load_and_resize_image("images/password_strength_medium.png", image_size)
img_weak = load_and_resize_image("images/password_strength_weak.png", image_size)
img_very_weak = load_and_resize_image("images/password_strength_very_weak.png", image_size)

# Create an variable to store the user-input
var = tk.StringVar()
var.trace_add("write", entryPassword_change)

# Create the label to indicates the user to type a password
labelTypePassword = tk.Label(root, text="Please type a password to verify :", pady=10)
labelTypePassword.pack()

# Create the entry to type the password
entryPassword = tk.Entry(root, show="*", textvariable=var, width=50)
entryPassword.pack()

# Create the label to display password strength
labelStrength = tk.Label(root, text="Password Strength: ", pady=10)
labelStrength.pack()

# Create the label to display password strength image
labelImage = tk.Label(root, image=img_very_weak, width=241, height=141)
labelImage.pack()

# Create the button to validate the password
buttonValidatePassword = tk.Button(root, text="Validate", command=buttonValidatePassword_click)
buttonValidatePassword.pack()

root.mainloop()
