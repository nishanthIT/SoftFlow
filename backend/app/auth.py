import hashlib,hmac,time,secrets
from fastapi import Cookie, HTTPException
from .config import settings

def token(username):
    body=f'{username}:{int(time.time())+28800}'
    return body+':'+hmac.new(settings.auth_secret.encode(),body.encode(),hashlib.sha256).hexdigest()
def require_user(sentinel_session: str | None=Cookie(default=None)):
    try:
        username,expires,signature=(sentinel_session or '').rsplit(':',2)
        body=f'{username}:{expires}'
        valid=hmac.compare_digest(signature,hmac.new(settings.auth_secret.encode(),body.encode(),hashlib.sha256).hexdigest())
        if not valid or int(expires)<time.time() or username!=settings.admin_username: raise ValueError()
        return username
    except (ValueError,TypeError): raise HTTPException(401,'Sign in required')
