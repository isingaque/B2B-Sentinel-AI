from datetime import datetime, timedelta, timezone
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models import User

hasher = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)

def make_token(user: User):
    expiry = datetime.now(timezone.utc) + timedelta(hours=12)
    token = jwt.encode({"sub": user.id, "exp": expiry, "role": user.role}, settings.jwt_secret, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "expires_in": 43200, "user": user_json(user)}

def user_json(user: User):
    return {"id": user.id, "username": user.username, "role": user.role}

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(401, "Authentication required")
    try:
        payload = jwt.decode(credentials.credentials, settings.jwt_secret, algorithms=["HS256"])
        uid = payload["sub"]
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(401, "Invalid or expired token")
    user = db.get(User, uid)
    if not user:
        raise HTTPException(401, "Account not found")
    return user

def operator(user: User = Depends(current_user)):
    return user

def admin(user: User = Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Administrator required")
    return user
