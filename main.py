from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import jwt
import os

app = FastAPI()

# Настройки
SECRET_KEY = os.getenv("SECRET_KEY", "access-secret")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", "refresh-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Модели
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    email: str
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

# База пользователей
fake_users_db = {
    "john": {
        "username": "john",
        "full_name": "John Wick",
        "email": "john@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    }
}

# Утилиты
def verify_password(plain_password, hashed_password):
    return "fakehashed" + plain_password == hashed_password

def get_user(username: str):
    user = fake_users_db.get(username)
    return UserInDB(**user) if user else None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_token(data: dict, secret: str, expires_delta: timedelta):
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + expires_delta
    return jwt.encode(to_encode, secret, algorithm=ALGORITHM)

def decode_token(token: str, secret: str):
    return jwt.decode(token, secret, algorithms=[ALGORITHM])

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_token({"sub": user.username}, SECRET_KEY, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token({"sub": user.username}, REFRESH_SECRET_KEY, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str = Form(...)):
    try:
        payload = decode_token(refresh_token, REFRESH_SECRET_KEY)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        access_token = create_token({"sub": username}, SECRET_KEY, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        new_refresh_token = create_token({"sub": username}, REFRESH_SECRET_KEY, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
        return {"access_token": access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@app.get("/users/me", response_model=User)
async def read_users_me(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_token(token, SECRET_KEY)
        username = payload.get("sub")
        user = get_user(username)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token is invalid or expired")
