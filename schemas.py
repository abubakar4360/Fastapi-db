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

class AdminBase(BaseModel):
    username: str

    class Config:
        orm_mode = True

class AdminCreate(AdminBase):
    password: str

class Admin(AdminBase):
    id: int

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: str

