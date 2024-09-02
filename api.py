from datetime import timedelta, datetime
from fastapi import FastAPI, Request, Depends, HTTPException, Form, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.templating import Jinja2Templates
import jwt
from starlette.responses import HTMLResponse
from utils.util import (SECRET_KEY, RESET_SECRET_KEY, VERIFICATION_SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES,
						send_email, create_access_token)
from schemas.model import UserModel, EmployeeModel
from schemas.schemas import User, EmployeeCreate, EmployeeUpdate, EmployeeBase
from schemas.db import get_db

app = FastAPI()
templates = Jinja2Templates(directory="templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = db.query(UserModel).filter(UserModel.name == username).first()
        if user is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    return user


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post('/signup')
def create_user(user: User, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
	existing_user = db.query(UserModel).filter(UserModel.name == user.name or UserModel.name == user.name).first()

	if existing_user:
		raise HTTPException(status_code=409, detail='User already exists')
	new_user = UserModel(name=user.name, email=user.email, password=pwd_context.hash(user.password))
	db.add(new_user)
	db.commit()
	db.refresh(new_user)

	# Send verification email
	verification_token = jwt.encode({'sub': new_user.email, 'exp': datetime.utcnow() + timedelta(minutes=15)}, VERIFICATION_SECRET_KEY, algorithm=ALGORITHM)
	verification_link = f"http://127.0.0.1:8000/verify_email?token={verification_token}"

	body = f"Click the link to verify your account: {verification_link}"
	background_tasks.add_task(send_email, '"Verify your account"', new_user.email, body)

	return {"message": "User created! Please verify your email."}

@app.get('/verify_email')
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, VERIFICATION_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        user = db.query(UserModel).filter(UserModel.email == email).first()
        if not user or user.is_verified:
            raise HTTPException(status_code=400, detail="Invalid or already verified user")
        user.is_verified = True
        db.commit()
        return {"message": "Email verified successfully!"}
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

@app.post('/login')
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
	existing_user = db.query(UserModel).filter(UserModel.name == form_data.username).first()

	if not existing_user or not pwd_context.verify(form_data.password, existing_user.password):
		raise HTTPException(status_code=401, detail='Incorrect username or password')
	if not existing_user.is_verified:
		raise HTTPException(status_code=401, detail='Email not verified!')

	access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
	access_token = create_access_token(data={"sub": existing_user.name}, expires_delta=access_token_expires)

	return {"access_token": access_token, "token_type": "bearer"}

@app.post('/forget_password')
def forgot_password(background_tasks: BackgroundTasks, email: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User with this email does not exist")

    reset_token = jwt.encode({'sub': user.email, 'exp': datetime.utcnow() + timedelta(minutes=15)}, RESET_SECRET_KEY, algorithm=ALGORITHM)
    reset_link = f"http://127.0.0.1:8000/reset_password_form?token={reset_token}"
    body = f"Click the link to reset your password: {reset_link}"
    background_tasks.add_task(send_email, "Reset your password", user.email, body)

    return {"message": "Password reset reset link sent to your email!"}

@app.get('/reset_password_form')
async def reset_password_form(token: str, request: Request):
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})


@app.post('/reset_password')
def reset_password(token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, RESET_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token")

        user = db.query(UserModel).filter(UserModel.email == email).first()
        if not user:
            raise HTTPException(status_code=400, detail="User does not exist")

        user.password = pwd_context.hash(new_password)
        db.commit()

        return {"message": "Password reset successfully!"}
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

@app.post('/add_employee', response_model=EmployeeCreate)
def add_employee(request: EmployeeCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
	employee = db.query(EmployeeModel).filter(EmployeeModel.id == request.id).first()
	if employee:
		raise HTTPException(status_code=400, detail=f"Employee with ID {request.id} already exists!")

	new_employee = EmployeeModel(id=request.id, name=request.name, email=request.email)
	db.add(new_employee)
	db.commit()
	db.refresh(new_employee)

	return new_employee


@app.get("/get_employees")
def get_employees(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
	if db.query(EmployeeModel).count() == 0:
		return {"message": "No employees yet!"}
	return db.query(EmployeeModel).all()

@app.post('/read_employee')
def read_employee(request: EmployeeBase, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
	employee = db.query(EmployeeModel).filter(EmployeeModel.id == request.id).first()
	if employee:
		return {"Employee Info": {"id": employee.id, "name": employee.name, "email": employee.email}}

	raise HTTPException(status_code=404, detail=f"Employee with ID {request.id} does not exist")


@app.post('/update_employee')
def update_employee(request: EmployeeUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
	employee = db.query(EmployeeModel).filter(EmployeeModel.id == request.id).first()
	if not employee:
		raise HTTPException(status_code=404, detail=f"Employee with ID {request.id} does not exist")

	if request.name:
		employee.name = request.name
	if request.email:
		employee.email = request.email
	db.commit()
	db.refresh(employee)

	return {"message": f"Employee with ID {request.id} updated"}


@app.post('/delete_employee')
def delete_employee(request: EmployeeBase, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
	employee = db.query(EmployeeModel).filter(EmployeeModel.id == request.id).first()
	if not employee:
		raise HTTPException(status_code=404, detail=f"Employee with ID {request.id} does not exist")

	db.delete(employee)
	db.commit()

	return {"message": f"Employee with ID {request.id} deleted"}

