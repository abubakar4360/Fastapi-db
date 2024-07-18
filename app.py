from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from database import Base, engine, add_new_employee, delete_employee, view_employees, get_db, add_admin, get_admin
from model import Employee as EmployeeModel, Admin as AdminModel
from schemas import Employee as EmployeeSchema, Admin as AdminSchema, Token, TokenData
import secrets

app = FastAPI()

# Define the secret key and algorithm for JWT
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin/token")

async def authenticate_user(username: str, password: str, db: Session) -> AdminModel:
    user = db.query(AdminModel).filter(AdminModel.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    return user

def create_access_token(*, data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_admin(token: str = Depends(oauth2_scheme)) -> AdminModel:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_admin(engine)  # Assuming get_admin is a function to fetch admin from the database
    if user is None:
        raise credentials_exception
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not an admin"
        )
    return user

@app.post("/admin/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post('/employees/', response_model=EmployeeSchema)
def create_employee(employee: EmployeeSchema, db: Session = Depends(get_db), current_admin: AdminModel = Depends(get_current_admin)):
    db_employee = db.query(EmployeeModel).filter(EmployeeModel.email == employee.email).first()
    if db_employee:
        raise HTTPException(status_code=400, detail='Email already registered')
    return add_new_employee(db, employee)

@app.delete('/employees/{employee_id}', response_model=EmployeeSchema)
def remove_employee(employee_id: int, db: Session = Depends(get_db), current_admin: AdminModel = Depends(get_current_admin)):
    employee = db.query(EmployeeModel).filter(EmployeeModel.id == employee_id).first()
    if employee is None:
        raise HTTPException(status_code=404, detail='Employee not found')
    if delete_employee(db, employee_id):
        return employee
    raise HTTPException(status_code=400, detail='Failed to delete employee')

@app.get('/employees/{employee_id}', response_model=EmployeeSchema)
def read_employee(employee_id: int, db: Session = Depends(get_db), current_admin: AdminModel = Depends(get_current_admin)):
    employee = db.query(EmployeeModel).filter(EmployeeModel.id == employee_id).first()
    if employee is None:
        raise HTTPException(status_code=404, detail='Employee not found')
    return employee

@app.get('/employees/', response_model=List[EmployeeSchema])
def view_all_employees(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_admin: AdminModel = Depends(get_current_admin)):
    employees = db.query(EmployeeModel).offset(skip).limit(limit).all()
    return employees
