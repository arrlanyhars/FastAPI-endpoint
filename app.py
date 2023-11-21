from fastapi import FastAPI, HTTPException, Depends, status
from sqlalchemy import create_engine, Column, Integer, String, Enum as SQLAlchemyEnum, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional
from datetime import date, datetime, timedelta
from pydantic import BaseModel

##############
### SET UP ###
##############

# Variabel Aplikasi Fast API
app = FastAPI()

# Inisialisasi objek CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Konfigurasi Database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine) #sesi database
Base = declarative_base() #base SQLAlchemy

# Membuat tabel
Base.metadata.create_all(bind=engine)


##############
### FUNGSI ###
##############

# Fungsi untuk verifikasi password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Fungsi untuk mendapatkan hash password
def get_password_hash(password):
    return pwd_context.hash(password)

# Fungsi untuk Create Token
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, "secret-key", algorithm="HS256")
    return encoded_jwt

# Fungsi untuk Mendapatkan User dari Database
def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

# Fungsi untuk Verifikasi Token
def verify_token(db: Session, token: str, credentials_exception):
    credentials = jwt.decode(token, "secret-key", algorithms=["HS256"])
    username: str = credentials["sub"]
    if username is None:
        raise credentials_exception
    return username

# Fungsi untuk mendapatkan sesi database
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


##############
### MODEL ###
##############

# Model User
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    nama = Column(String, index=True)
    jenis_kelamin = Column(Integer, index=True)
    tanggal_lahir = Column(Date, nullable=True, index=True)

# Model untuk login
class UserLogin(BaseModel):
    username: str
    password: str

# Model untuk input user
class InputUser(BaseModel):
    username: str
    nama: str
    jenis_kelamin: Optional[int]
    tanggal_lahir: Optional[date]
    password: str


###############
### OPERASI ###
###############

# Login => Operasi untuk login
@app.post("/login")
async def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = get_user(db, user.username)
    if db_user is None or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

# Membuat tag dengan nama Users
tags_metadata = [
    {
        "name": "Users",
        "description": "Jenis Kelamin:\n\n"
        "-1: Laki -Laki\n\n"
        "-2: Perempuan\n\n"
        "Parameter jenis_kelamin dan tanggal_lahir adalah optional. "
        "Jadi bisa disertakan jika memang akan diubah."
    }
]
app.openapi_tags = tags_metadata

# Create User => Operasi untuk membuat user baru
@app.post("/users", tags=["Users"])
def create_user(input_user: InputUser, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(input_user.password)
    db_user = User(
        username=input_user.username,
        nama=input_user.nama,
        hashed_password=hashed_password,
        jenis_kelamin=input_user.jenis_kelamin,
        tanggal_lahir=input_user.tanggal_lahir,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    db.close()
    return db_user

# Daftar User => Operasi untuk melihat semua user
@app.get("/users/daftar", tags=["Users"])
def daftar_user():
    db = SessionLocal()
    result_users = db.query(User).all()
    db.close()
    return result_users

# Get User => Operasi untuk melihat detail user berdasarkan ID user
@app.get("/users/{user_id}", tags=["Users"])
def get_users(user_id: int):
    db = SessionLocal()
    user = db.query(User).filter(User.id == user_id).first()
    db.close()
    if user is None:
        raise HTTPException(status_code=404, detail="User tidak ditemukan.")
    return user

# Delete User => Operasi untuk menghapus user berdasarkan ID user
@app.delete("/users/{user_id}", tags=["Users"])
def delete_user(user_id: int):
    db = SessionLocal()
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        db.close()
        raise HTTPException(status_code=404, detail="User tidak ditemukan.")
    db.delete(user)
    db.commit()
    db.close()
    return {"message": f"User dengan ID {user_id} berhasil dihapus."}

# Update User => Operasi untuk mengupdate data user berdasarkan ID user
@app.put("/users/{user_id}", tags=["Users"])
def update_user(user_id: int, input_user: InputUser):
    db = SessionLocal()
    existing_user = db.query(User).filter(User.id == user_id).first()
    if existing_user is None:
        db.close()
        raise HTTPException(status_code=404, detail="User tidak ditemukan.")
    existing_user.nama = input_user.nama
    existing_user.jenis_kelamin = input_user.jenis_kelamin
    existing_user.tanggal_lahir = input_user.tanggal_lahir

    db.commit()
    db.close()
    return {"message": f"User dengan ID {user_id} berhasil diupdate."}
