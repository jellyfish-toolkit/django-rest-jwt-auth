class AuthError:
    WRONG_DATA_FORMAT = 'Incorrect data format, JSON expected'
    WRONG_TOKEN = 'Invalid token'
    WRONG_EMAIL = 'Invalid email'
    WRONG_DATA_FIELDS = 'Incorrect data fields'

    FIELDS_REQUIRED = "'username' and 'password' fields are required"
    FIELDS_REQUIRED_REGISTR = "'email' and 'password' fields are required"
    FIELDS_REQUIRED_REGISTR_CHOICE = "'username' or 'email_as_name' field is required. If both - 'username' is prior"

    USER_EXISTS = 'User with such username already exists'
    EMAIL_EXISTS = 'User with such email already exists'
    USER_NOT_FOUND = 'User not found'

    POST_JSON = 'Only POST method, only JSON data'
    NO_AUTH_TOKEN = 'No Autherization token'

    EMAIL_WASNT_SENT = 'Email wasnt sent'
    TOKEN_EXPIRED = 'Token expired'
