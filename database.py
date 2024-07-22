from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from model import Base

db_url = 'sqlite:///./login.db'

engine = create_engine(db_url, connect_args={'check_same_thread' : False})
SessionLocal = sessionmaker(autoflush=False, autocommit=False, bind=engine)
Base.metadata.create_all(bind=engine)