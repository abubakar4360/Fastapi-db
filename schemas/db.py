from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from schemas.model import Base

engine = create_engine('sqlite:///employee.db')
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def get_db():
	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()