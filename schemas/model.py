from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class EmployeeModel(Base):
	__tablename__ = 'employee'

	id = Column(Integer, primary_key=True, autoincrement=True, nullable=False, unique=True)
	name = Column(String(50), nullable=False)
	email = Column(String(50), nullable=False, unique=True)

class UserModel(Base):
	__tablename__ = 'user'

	id = Column(Integer, primary_key=True, autoincrement=True)
	name = Column(String(50), nullable=False, unique=True)
	email = Column(String(50), nullable=False, unique=True)
	password = Column(String(50), nullable=False)
	is_verified = Column(Boolean, default=False)