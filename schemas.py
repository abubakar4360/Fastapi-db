from pydantic import BaseModel

class Employee(BaseModel):
    id: int
    name: str
    email: str
    age: int
    salary: int
    role: str

    class Config:
        orm_mode = True

class AdminCreate(BaseModel):
    username: str
    password: str

class Admin(BaseModel):
    username: str
    password: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
