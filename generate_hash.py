# generate_hash.py
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

plain_password = "password"  # или любой другой пароль
hashed_password = pwd_context.hash(plain_password)

print("Hashed password:", hashed_password)