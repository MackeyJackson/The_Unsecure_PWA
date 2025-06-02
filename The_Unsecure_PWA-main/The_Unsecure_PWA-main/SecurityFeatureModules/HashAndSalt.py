import bcrypt
def SaltAndHash(password):
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    HashedPassword = bcrypt.hashpw(bytes, salt)
    print(HashedPassword)
    return HashedPassword

def check_password(InputPassword, Hash):
    userBytes = InputPassword.encode('utf-8') 
    result = bcrypt.checkpw(userBytes, Hash)
    return result