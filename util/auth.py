def extract_credentials(request):
    body = request.body.decode('utf-8')
    # split body into parts
    parts = body.split('&')
    credentials = {}

    for part in parts:
        key, value = part.split('=', 1)

        value = value.replace('+', ' ')
        decoded_value = ''
        i = 0
        while i < len(value):
            if value[i] == '%' and i + 2 < len(value):
                decoded_value += chr(int(value[i+1:i+3], 16))
                i += 3
            else:
                decoded_value += value[i]
                i += 1
        credentials[key] = decoded_value

    # login or registration based on the keys present
    if 'username_reg' in credentials and 'password_reg' in credentials:
        username = credentials['username_reg']
        password = credentials['password_reg']
    elif 'username_login' in credentials and 'password_login' in credentials:
        username = credentials['username_login']
        password = credentials['password_login']
    else:
        # edge case
        username = ''
        password = ''

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
    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&()-_=" for c in password):
        return False
    return True