from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class UserTable(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(20), nullable=False)
    is_verified = Column(Boolean)

class EmployeeTable(Base):
    __tablename__ = 'employee'

    id = Column(Integer, primary_key=True, unique=True)
    name =Column(String(100), nullable=False)
    age = Column(Integer)
    email = Column(String(100), unique=True, nullable=False)
    role = Column(String(100), nullable=False)
    salary = Column(Integer, nullable=False)

class TokenTable(Base):
    __tablename__ = 'token'

    user_id = Column(Integer)
    access_token = Column(String(100), primary_key=True)
    refresh_token = Column(String(100), nullable=False)
    status = Column(Boolean)
    created_date = Column(DateTime, default=datetime.datetime.now)