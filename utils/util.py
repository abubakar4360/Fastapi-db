from datetime import timedelta, datetime
from typing import Optional
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets

SECRET_KEY = secrets.token_hex(32)
VERIFICATION_SECRET_KEY = secrets.token_hex(32)
RESET_SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
	to_encode = data.copy()

	if expires_delta:
		expire = datetime.utcnow() + expires_delta
	else:
		expire = datetime.utcnow() + timedelta(minutes=15)
	to_encode.update({"exp": expire})
	encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
	return encoded_jwt

def send_email(subject: str, recipient: str, body: str):
    email = "abubakarabbasi1000@gmail.com"
    password = "tmvl mgad mmpy mllu"
    smtp_server = "smtp.gmail.com"
    port = 465

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

