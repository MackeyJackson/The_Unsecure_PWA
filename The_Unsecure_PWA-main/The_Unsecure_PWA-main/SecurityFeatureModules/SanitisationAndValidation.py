import re
import html

banned_characters = ['<', '>', '"', "'", ';', '=', '(', ')', '&', '$', '%', '`','/', '\\', '#', ':', ',', '@', '~', '+']

def CheckEmail(email):
    if not isinstance(email, str):
        raise TypeError("Email must be a string")
    Emailparameters = r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$" 
    Checker = re.match(Emailparameters, email)
    if Checker == None:
        raise ValueError("Invalid Email Adress")
    if not re.match("^[a-zA-Z0-9._@-]+$", email):
        raise ValueError("Invalid Email Adress")
    return True

def MakeWebSafe(string):
    SafeString = html.escape(string)
    return SafeString

def validatePassword(password):
    SpecialCharacters = "@$!%*?&"
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    match password:
        case i if not (8 <= len(password) <= 20):
            raise ValueError("Password must be between 8 and 20 characters")
        case i if " " in password:
            raise ValueError("Password cannot contain spaces")
        case i if all(c.isupper() for c in password if c.isalpha()):
            raise ValueError("Password must contain at least one lowercase letter (a–z)")
        case i if all(c.islower() for c in password if c.isalpha()):
            raise ValueError("Password must contain at least one uppercase letter (A–Z)")
        case i if all(c not in SpecialCharacters for c in password):
            raise ValueError("Password must contain at least one special character (@$!%*?&)")
        case i if all(not c.isdigit() for c in password):
            raise ValueError("Password must contain at least one number (0-9)")
    if not re.match("^[a-zA-Z0-9@$!%*?&]+$", password): #whitelist
        raise ValueError("Password can only contain letters, numbers and special characters (@$!%*?&)")
    return True
        
def ValidateName(name):
    name = name.strip()
    if len(name) < 4 or len(name) > 15:
        raise ValueError("Username must be between 433 and 10 characters")
    if not isinstance(name, str):
        raise TypeError("Username must be a string")
    if not re.match("^[a-zA-Z0-9._]+$", name):
        raise ValueError("Username can only contain letters, numbers, dots and underscores")
    if name[-1] == (".","_") or name[0] == (".""_"):
        raise ValueError("Username cannot end or start in a special character")
    return True

def onlynum(code):
    return code.isdigit()

def ValidateNumber(number):
    if not isinstance(number, str):
        raise TypeError("Name must be a string")
    if not number.isnumeric():
        raise ValueError("Number must consists only of numeric characters")
    return True

def validateComment(comment):
    if not isinstance(comment, str):
        raise TypeError("Comment must be a string")
    comment = comment.strip()
    if len(comment) == 0:
        raise ValueError("Comment cannot be empty")
    if len(comment) > 50:
        raise ValueError("Comment is too long (max 50 characters)")
    if not any(char.isalnum() for char in comment):
        raise ValueError("Comment must contain readable text")
    if re.search(r"[<>\"'`\\;]", comment):
        raise ValueError("Comment contains invalid characters")
    return True
