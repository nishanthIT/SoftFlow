"""Build sandbox authentication without sending malformed or empty credentials."""


class InvalidSandboxToken(ValueError):
    pass


def headers(kind, token):
    token = token.strip()
    if not token:
        # Classic Cuckoo may intentionally allow anonymous API requests. Let an
        # authenticated server return 401 instead of sending invalid 'Bearer '.
        return {}
    if not token.isascii() or any(ord(character) <= 32 or ord(character) == 127 for character in token):
        raise InvalidSandboxToken('Sandbox API token must contain only printable characters without spaces')
    return {'Authorization': ('Bearer ' if kind == 'cuckoo' else 'Token ') + token}
