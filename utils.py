from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
import secrets
from typing import Optional, Union, Any

JWT_ACCESS_SECRET_TOKEN = secrets.token_hex(32)
JWT_REFRESH_SECRET_TOKEN = secrets.token_hex(32)

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def get_password_hash(passowrd: str) -> str:
    return pwd_context.hash(passowrd)

def verify_password(password: str, hash_password: str) -> bool:
    return pwd_context.verify(password, hash_password)

# def create_access_token(subject: Union[str, Any], expires_delta: timedelta = None) -> str:
#     if expires_delta is None:
#         expires_delta = timedelta(minutes=30)
#
#     to_encode = {'sub': str(subject), 'exp': datetime.utcnow() + expires_delta}
#     encoded_jwt = jwt.encode(to_encode, JWT_ACCESS_SECRET_TOKEN, algorithm='HS256')
#
#     return encoded_jwt

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_ACCESS_SECRET_TOKEN, algorithm='HS256')
    return encoded_jwt

def create_refresh_token(subject: Union[str | Any], expires_delta: timedelta = None) -> str:
    if expires_delta is None:
        expires_delta = timedelta(minutes=24*60)

    to_encode = {'sub': str(subject), 'exp': datetime.utcnow() + expires_delta}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_TOKEN, algorithm='HS256')

    return encoded_jwt

def decode_access_token(token: str):
    try:
        decoded = jwt.decode(token, JWT_ACCESS_SECRET_TOKEN, algorithms=["HS256"])
        return decoded if decoded["exp"] >= datetime.utcnow() else None
    except jwt.PyJWTError:
        return None

def decode_refresh_token(token: str):
    try:
        decoded = jwt.decode(token, JWT_REFRESH_SECRET_TOKEN, algorithms=["HS256"])
        return decoded if decoded["exp"] >= datetime.utcnow() else None
    except jwt.PyJWTError:
        return None
