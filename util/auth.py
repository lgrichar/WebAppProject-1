def extract_credentials(request):
    # Assuming the request body is URL encoded
    body = request.body.decode('utf-8')
    # Split the body into 'username=...' and 'password=...' parts
    parts = body.split('&')
    credentials = {}
    for part in parts:
        key, value = part.split('=', 1)
        credentials[key] = value.replace('+', ' ')  # Replace '+' with space

    # Username is assumed not to be percent-encoded
    username = credentials.get('username', '')

    # Decode percent-encoded characters in password
    password = ''
    if 'password' in credentials:
        password = ''
        i = 0
        while i < len(credentials['password']):
            if credentials['password'][i] == '%' and i + 2 < len(credentials['password']):
                password += chr(int(credentials['password'][i+1:i+3], 16))
                i += 3
            else:
                password += credentials['password'][i]
                i += 1

    return [username, password]

def validate_password(password):
    if len(password) < 8:
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in "!@#$%^&()-_=+" for c in password):
        return False
    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&()-_=+" for c in password):
        return False
    return True