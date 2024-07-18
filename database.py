from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from model import Employee as EmployeeModel, Admin as AdminModel
from model import Base
from schemas import Employee as EmployeeSchema, AdminCreate as AdminCreateSchema
from passlib.context import CryptContext

SQLALCHEMY_DB_URL = "sqlite:///employee.db"
engine =  create_engine(SQLALCHEMY_DB_URL, connect_args={'check_same_thread': False})
SessionLocal = sessionmaker(autoflush=False, autocommit=False, bind=engine)
Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def add_new_employee(db: Session, employee: EmployeeSchema):
    db_new_employee = EmployeeModel(
        id = employee.id,
        name = employee.name,
        email = employee.email,
        age = employee.age,
        salary = employee.salary,
        role =employee.role
    )
    db.add(db_new_employee)
    db.commit()
    db.refresh(db_new_employee)
    return db_new_employee

def delete_employee(db: Session, employee_id: int):
    db_del_employee = db.query(EmployeeModel).filter(EmployeeModel.id == employee_id).first()
    if db_del_employee:
        db.delete(db_del_employee)
        db.commit()
        return True
    return False

def get_password_hash(password):
    return pwd_context.hash(password)

def add_admin(db: Session, admin: AdminCreateSchema):
    db_admin = AdminModel(
        username=admin.username,
        hashed_password=get_password_hash(admin.password)
    )
    db.add(db_admin)
    db.commit()
    db.refresh(db_admin)
    return db_admin

def update_admin_password(username: str, new_password: str, db: Session):
    admin = db.query(AdminModel).filter(AdminModel.username == username).first()
    if admin:
        hashed_password = get_password_hash(new_password)
        admin.hashed_password = hashed_password
        db.commit()
        db.refresh(admin)
        return admin
    return None


def get_admin(db: Session, username: str):
    return db.query(AdminModel).filter(AdminModel.username == username).first()


