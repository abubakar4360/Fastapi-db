from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from model import UserTable, TokenTable, EmployeeTable
from schemas import UserCreate, User, Token, RequestDetails, Employee, ChangePassword, ResetPasswordRequest, \
    ForgotPasswordRequest, Data
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from utils import (get_password_hash, verify_password, create_access_token, create_refresh_token, decode_refresh_token,
                   JWT_ACCESS_SECRET_TOKEN)
import jwt
from fastapi.security import OAuth2PasswordBearer
from database import SessionLocal
from dotenv import load_dotenv
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import secrets

load_dotenv()
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

VERIFICATION_SECRET_KEY = secrets.token_hex(32)
JWT_SECRET_KEY = secrets.token_hex(32)
VERIFICATION_TOKEN_EXPIRE_MINUTES = 30
RESET_SECRET_KEY = secrets.token_hex(32)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(UserTable).filter(UserTable.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate credentials",
                                          headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms="HS256")
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = Data(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(UserTable).filter(UserTable.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

def send_email(subject: str, recipient: str, body: str):
    email = os.getenv("MAIL_USERNAME")
    password = os.getenv("MAIL_PASSWORD")
    smtp_server = os.getenv("MAIL_SERVER")
    port = int(os.getenv("MAIL_PORT"))

    msg = MIMEMultipart()
    msg['From'] = email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP_SSL(smtp_server, port) if port == 465 else smtplib.SMTP(smtp_server, port) as server:
            if port != 465:
                server.starttls()
            server.login(email, password)
            server.send_message(msg)
            print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")


@app.post('/register_user', response_model=User)
def register_user(register: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # Check for existing user
    taken_username = db.query(UserTable).filter(UserTable.username == register.username).first()
    taken_email = db.query(UserTable).filter(UserTable.email == register.email).first()

    if taken_username:
        raise HTTPException(status_code=400, detail='Username Already registered!')
    elif taken_email:
        raise HTTPException(status_code=400, detail='Email Already registered!')
    else:
        # Add new user
        new_user = UserTable(
            first_name=register.first_name,
            last_name=register.last_name,
            username=register.username,
            email=register.email,
            password=get_password_hash(register.password),
            is_verified=False
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        verification_token = jwt.encode({'sub': new_user.email, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                                        VERIFICATION_SECRET_KEY, algorithm='HS256')
        verification_link = f"http://127.0.0.1:8000/verify-email?token={verification_token}"

        subject = "Verify Email"
        body = f"Please verify your email by clicking the following link: {verification_link}"

        background_tasks.add_task(send_email, subject, new_user.email, body)

        # message = status.HTTP_201_CREATED
        # return {'message': message}
        return new_user


@app.get('/verify_user_email')
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, VERIFICATION_SECRET_KEY, algorithms='HS256')
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token.")
    except:
        raise HTTPException(status_code=400, detail="Invalid token.")

    user = db.query(UserTable).filter(UserTable.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail='Email not found.')

    if user.is_verified:
        return {"message": "Email already verified."}

    user.is_verified = True
    db.commit()

    return {"message": "Verification successful, you can now log in."}


# @app.post('/login_user', response_model=Token)
# def login(request: RequestDetails, db: Session = Depends(get_db)):
#     user = db.query(UserTable).filter(UserTable.email == request.email).first()
#     if user is None:
#         raise HTTPException(status_code=400, detail='Username does not exist.')
#
#     if not verify_password(request.password, user.password):
#         raise HTTPException(status_code=400, detail='Incorrect Password!')
#
#     if not user.is_verified:
#         raise HTTPException(status_code=400, detail='Email not verified.')
#
#     access = create_access_token(user.username)
#     refresh = create_refresh_token(user.username)
#
#     token_db = TokenTable(
#         user_id=user.id,
#         access_token=access,
#         refresh_token=refresh,
#         is_valid=True
#     )
#
#     db.add(token_db)
#     db.commit()
#     db.refresh(token_db)
#
#     return Token(access_token=access, refresh_token=refresh)


@app.post('/change_password')
def change_password(request: ChangePassword, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.email == request.email).first()
    if not user:
        raise HTTPException(status_code=400, detail='Invalid email.')

    if not verify_password(request.current_password, user.password):
        raise HTTPException(status_code=400, detail='Invalid password.')

    new_password = get_password_hash(request.new_password)
    user.password = new_password
    db.commit()

    return {"message": "Password changed successfully."}


@app.post('/forget_password')
def forgot_password(request: ForgotPasswordRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.email == request.email).first()
    if not user:
        raise HTTPException(status_code=400, detail='User does not exist.')

    reset_token = jwt.encode({'sub': user.email, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                             RESET_SECRET_KEY, algorithm='HS256')

    subject = "Reset Password"
    body = f"Use this token to reset the password: {reset_token}"

    background_tasks.add_task(send_email, subject, user.email, body)

    return {"message": "Password reset email has been sent."}


@app.post('/reset_password')
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(request.token, RESET_SECRET_KEY, algorithms='HS256')
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    user = db.query(UserTable).filter(UserTable.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail='Email not found.')

    user.password = get_password_hash(request.new_password)
    db.commit()

    return {"message": "Password has been reset successfully."}


@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(user.email)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post('/employees', response_model=Employee)
def add_employee(request: Employee, db: Session = Depends(get_db), current_user: UserTable = Depends(get_current_user)):
    employee = db.query(EmployeeTable).filter(EmployeeTable.email == request.email).first()
    if employee:
        raise HTTPException(status_code=400, detail='Email already registered.')

    new_employee = EmployeeTable(
        id=request.id,
        name=request.name,
        age=request.age,
        email=request.email,
        role=request.role,
        salary=request.salary
    )
    db.add(new_employee)
    db.commit()
    db.refresh(new_employee)

    return new_employee