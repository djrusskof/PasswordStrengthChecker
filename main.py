import tkinter as tk
from PIL import Image, ImageTk
import re
import ctypes


'''
    Password Strength Checker
    This program is a simple password strength checker that allows the user to type a password and see its strength.
    The password strength is calculated based on the following criteria:
    - Length >= 8
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - Less than 30% repeated characters
    - No sequences of 3 or more repeated characters
    The program also allows the user to show/hide the password and copy it to the clipboard.
    The password strength is displayed as a text and an image.
    The image changes based on the password strength.
    The program uses tkinter for the GUI and PIL for image manipulation.
    The program is a single file and can be run directly.
'''


VERY_STRONG_PASSWORD = "Very Strong"
STRONG_PASSWORD = "Strong"
MEDIUM_PASSWORD = "Medium"
WEAK_PASSWORD = "Weak"
VERY_WEAK_PASSWORD = "Very Weak"

'''
Function to show/hide password
This function is called when the user clicks the show/hide password button.
It changes the password entry widget to show or hide the password.
It also changes the button image to indicate the current state.
'''
def buttonShowPassword_click():
    # If the password is currently shown, hide it and change the button image to show
    if entryPassword.cget("show") == "":
        entryPassword.config(show="*")
        buttonShowPassword.config(image=img_show)
    # Else, if the password is currently hidden, show it and change the button image to hide
    else:
        entryPassword.config(show="")
        buttonShowPassword.config(image=img_hide)


'''
Function to copy password to clipboard
This function is called when the user clicks the copy password button.
'''
def buttonCopyPassword_click():
    root.clipboard_clear()
    root.clipboard_append(entryPassword.get())

'''
Function called each time password entry is changed
'''
def entryPassword_change(*args):
    password = var.get()
    strength = calculatePasswordStrength(password)
    labelStrength.config(text=f"Password Strength: {strength}")
    update_strength_image(strength)

'''
Function to calculate password strength
This function calculates the password strength based on the following criteria:
- Length >= 8
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character
- Less than 30% repeated characters
- No sequences of 3 or more repeated characters
The function returns the password strength as a string.
'''
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
        return VERY_STRONG_PASSWORD
    elif strength_score == 6:
        return STRONG_PASSWORD
    elif strength_score == 5:
        return MEDIUM_PASSWORD
    elif strength_score == 4:
        return WEAK_PASSWORD
    else:
        return VERY_WEAK_PASSWORD

'''
Function to update the strength image based on the password strength
'''
def update_strength_image(strength):
    if strength == VERY_STRONG_PASSWORD:
        img = img_very_strong
    elif strength == STRONG_PASSWORD:
        img = img_strong
    elif strength == MEDIUM_PASSWORD:
        img = img_medium
    elif strength == WEAK_PASSWORD:
        img = img_weak
    else:
        img = img_very_weak
    labelImage.config(image=img)

'''
Function to load and resize an image
This function loads an image from a file and resizes it to the desired size.
It returns the image as a PhotoImage object.
'''
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
passwordStrengthImageSize = (241, 141)
passwordShowImageSize = (20, 15)

# Load images for different password strengths
img_very_strong = load_and_resize_image("images/password_strength_very_strong.png", passwordStrengthImageSize)
img_strong = load_and_resize_image("images/password_strength_strong.png", passwordStrengthImageSize)
img_medium = load_and_resize_image("images/password_strength_medium.png", passwordStrengthImageSize)
img_weak = load_and_resize_image("images/password_strength_weak.png", passwordStrengthImageSize)
img_very_weak = load_and_resize_image("images/password_strength_very_weak.png", passwordStrengthImageSize)

# Load image for show/hide password button
img_show = load_and_resize_image("images/eye_closed.png", passwordShowImageSize)
img_hide = load_and_resize_image("images/eye_opened.png", passwordShowImageSize)

# Create the top and bottom frames
top = tk.Frame(root)
bottom = tk.Frame(root)
top.pack(side=tk.TOP)
bottom.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

# Create an variable to store the user-input
var = tk.StringVar()
var.trace_add("write", entryPassword_change)

# Create the label to indicates the user to type a password
labelTypePassword = tk.Label(root, text="Please type a password to verify :", pady=10)
labelTypePassword.pack(in_=top)

# Create the entry to type the password
entryPassword = tk.Entry(root, show="*", textvariable=var, width=40)
entryPassword.pack(in_=top,side=tk.LEFT)

# Create the button to show the password
buttonShowPassword = tk.Button(root, image=img_show, command=buttonShowPassword_click)
buttonShowPassword.pack(in_=top,side=tk.RIGHT)

# Create the label to display password strength
labelStrength = tk.Label(root, text="Password Strength: ", pady=10)
labelStrength.pack()

# Create the label to display password strength image
labelImage = tk.Label(root, image=img_very_weak, width=241, height=141)
labelImage.pack()

# Create the button to copy password to clipboard
buttonCopyPassword = tk.Button(root, text="Copy password", command=buttonCopyPassword_click)
buttonCopyPassword.pack()

root.mainloop()
