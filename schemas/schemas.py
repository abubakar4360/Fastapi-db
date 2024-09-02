from pydantic import BaseModel
from typing import Optional

class EmployeeBase(BaseModel):
	id: int

class EmployeeCreate(EmployeeBase):
	name: str
	email: str

class EmployeeUpdate(EmployeeBase):
	name: Optional[str]
	email: Optional[str]

class User(BaseModel):
	name: str
	email: str
	password: str
