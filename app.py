from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from sqlalchemy.orm import Session
from model import UserTable, TokenTable
from schemas import UserCreate, Token, RequestDetails, TokenCreate, ChangePassword, ResetPasswordRequest, ForgotPasswordRequest
from database import SessionLocal
from utils import RESET_SECRET_KEY, ALGORITHM, VERIFICATION_SECRET_KEY
from utils import (
    get_password_hash, verify_password, create_access_token, create_refresh_token)
import jwt
from dotenv import load_dotenv
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta


load_dotenv()
app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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

@app.post('/register', response_model=UserCreate)
def register_user(register: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # Check for existing user
    already_registered = db.query(UserTable).filter((UserTable.username == register.username) | (UserTable.email == register.email)).first()
    if already_registered:
        raise HTTPException(status_code=400, detail='Username or Email Already registered!')

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
                                    VERIFICATION_SECRET_KEY, algorithm=ALGORITHM)
    verification_link = f"http://127.0.0.1:8000/verify-email?token={verification_token}"

    subject = "Verify Email"
    body = f"Please verify your email by clicking the following link: {verification_link}"

    background_tasks.add_task(send_email, subject, new_user.email, body)

    return new_user

@app.get('/verify-email')
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, VERIFICATION_SECRET_KEY, algorithms=ALGORITHM)
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token.")
    except jwt.JWTError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    user = db.query(UserTable).filter(UserTable.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail='Email not found.')

    if user.is_verified:
        return {"message": "Email already verified."}

    user.is_verified = True
    db.commit()

    return {"message": "Verification successful, you can now log in."}


@app.post('/login', response_model=Token)
def login(request: RequestDetails, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=400, detail='Username does not exist.')

    if not verify_password(request.password, user.password):
        raise HTTPException(status_code=400, detail='Incorrect Password!')

    if not user.is_verified:
        raise HTTPException(status_code=400, detail='Email not verified.')

    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)

    token_db = TokenTable(
        user_id=user.id,
        access_token=access,
        refresh_token=refresh,
        status=True
    )

    db.add(token_db)
    db.commit()
    db.refresh(token_db)

    return Token(access_token=access, refresh_token=refresh)


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

    return new_password

@app.post('/forget_password')
def forgot_password(request: ForgotPasswordRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.email == request.email).first()
    if not user:
        raise HTTPException(status_code=400, detail='User does not exist.')

    reset_token = jwt.encode({'sub': user.email, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                             RESET_SECRET_KEY, algorithm=ALGORITHM)

    subject = "Reset Password"
    body = f"Use this token to reset the password: {reset_token}"

    background_tasks.add_task(send_email, subject, user.email, body)

    return {"message": "Password reset email has been sent."}


@app.post('/reset_password')
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(request.token, RESET_SECRET_KEY, algorithms=ALGORITHM)
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token.")
    except jwt.JWTError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    user = db.query(UserTable).filter(UserTable.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail='Email not found.')

    user.password = get_password_hash(request.new_password)
    db.commit()

    return {"message": "Password has been reset successfully."}
