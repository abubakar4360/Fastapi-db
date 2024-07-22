from pydantic import BaseModel
import datetime

class UserBase(BaseModel):
    first_name: str
    last_name: str
    username: str
    email: str
    password: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int

class ChangePassword(BaseModel):
    email: str
    current_password: str
    new_password: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class RequestDetails(BaseModel):
    email: str
    password: str

class Employee(BaseModel):
    id: int
    name: str
    age: int
    email: str
    role: str
    salary: int

class Token(BaseModel):
    access_token: str
    refresh_token: str

class Data(BaseModel):
    username: str

class TokenCreate(BaseModel):
    user_id: str
    access_token: str
    refresh_token: str
    status: bool
    created_date: datetime.datetime