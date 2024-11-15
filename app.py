from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
import secrets
from passlib.context import CryptContext

from model import Employee as EmployeeModel, Admin as AdminModel
from database import add_new_employee, delete_employee, get_db, add_admin, get_admin, update_admin_password
from schemas import Employee as EmployeeSchema, AdminCreate as AdminCreateSchema, Admin as AdminSchema, Token, TokenData


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

# Define the secret key and algorithm for JWT
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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
    admin = get_admin(db, username=token_data.username)
    if admin is None:
        raise credentials_exception
    return admin

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    admin = get_admin(db, username=form_data.username)
    if not admin or not verify_password(form_data.password, admin.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": admin.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post('/admins/', response_model=AdminSchema)
def create_admin(admin: AdminCreateSchema, db: Session = Depends(get_db)):
    db_admin = db.query(AdminModel).filter(AdminModel.username == admin.username).first()
    if db_admin:
        raise HTTPException(status_code=400, detail='Username already registered')
    return add_admin(db, admin)

@app.put('/admins/', response_model=AdminSchema)
def update_password(username: str, current_password: str, new_password: str, db: Session = Depends(get_db)):
    check_account = db.query(AdminModel).filter(AdminModel.username == username and AdminModel.hashed_password == current_password)
    if check_account:
        return update_admin_password(username, new_password, db)
    elif db.query(AdminModel).filter(AdminModel.username == username):
        raise HTTPException(status_code=404, detail='Password incorrect.')
    else:
        raise HTTPException(status_code=404, detail='Account does not exists!')

@app.post('/add_employee/', response_model=EmployeeSchema)
def create_employee(employee: EmployeeSchema, db: Session = Depends(get_db), current_admin: AdminModel = Depends(get_current_admin)):
    db_employee = db.query(EmployeeModel).filter(EmployeeModel.email == employee.email).first()
    if db_employee:
        raise HTTPException(status_code=400, detail='Email already registered')
    return add_new_employee(db, employee)

@app.get('/view_employees/', response_model=List[EmployeeSchema])
def view_all_employees(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_admin: AdminModel = Depends(get_current_admin)):
    employees = db.query(EmployeeModel).offset(skip).limit(limit).all()
    return employees


@app.delete('/delete_employee/{employee_id}', response_model=EmployeeSchema)
def remove_employee(employee_id: int, db: Session = Depends(get_db), current_admin: AdminModel = Depends(get_current_admin)):
    employee = db.query(EmployeeModel).filter(EmployeeModel.id == employee_id).first()
    if employee is None:
        raise HTTPException(status_code=404, detail='Employee not found')
    if delete_employee(db, employee_id):
        return employee
    raise HTTPException(status_code=400, detail='Failed to delete employee')

@app.get('/employee_info/{employee_id}', response_model=EmployeeSchema)
def read_employee(employee_id: int, db: Session = Depends(get_db), current_admin: AdminModel = Depends(get_current_admin)):
    employee = db.query(EmployeeModel).filter(EmployeeModel.id == employee_id).first()
    if employee is None:
        raise HTTPException(status_code=404, detail='Employee not found')
    return employee

