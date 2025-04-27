from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import List, Optional
import os

DATABASE_URL = os.environ.get("DATABASE_URL")

SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    full_name = Column(String)
    role = Column(String, default="inspector")

class Inspection(Base):
    __tablename__ = "inspections"
    id = Column(Integer, primary_key=True, index=True)
    inspector_id = Column(Integer, ForeignKey("users.id"))
    facility_name = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    hvac_type = Column(String)
    # Add more fields as per your schema

# SQLAlchemy setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Schemas for request/response
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = ""
    role: Optional[str] = "inspector"

class UserOut(BaseModel):
    id: int
    username: str
    full_name: Optional[str]
    role: Optional[str]

    class Config:
        orm_mode = True

class InspectionCreate(BaseModel):
    facility_name: str
    latitude: Optional[float]
    longitude: Optional[float]
    hvac_type: Optional[str] = ""
    # Add more fields as per your schema

class InspectionOut(BaseModel):
    id: int
    facility_name: str
    latitude: Optional[float]
    longitude: Optional[float]
    hvac_type: Optional[str]
    inspector_id: int

    class Config:
        orm_mode = True

# ------------------------
# Auth Endpoints
# ------------------------
@app.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_pw = get_password_hash(user.password)
    db_user = User(username=user.username, password=hashed_pw, full_name=user.full_name, role=user.role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# ------------------------
# Inspections CRUD
# ------------------------
@app.post("/inspections", response_model=InspectionOut)
def create_inspection(item: InspectionCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    inspection = Inspection(
        inspector_id=current_user.id,
        facility_name=item.facility_name,
        latitude=item.latitude,
        longitude=item.longitude,
        hvac_type=item.hvac_type,
        # Set more fields as needed
    )
    db.add(inspection)
    db.commit()
    db.refresh(inspection)
    return inspection

@app.get("/inspections", response_model=List[InspectionOut])
def list_inspections(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Inspection).all()

@app.get("/inspections/{inspection_id}", response_model=InspectionOut)
def get_inspection(inspection_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    inspection = db.query(Inspection).filter(Inspection.id == inspection_id).first()
    if not inspection:
        raise HTTPException(status_code=404, detail="Not found")
    return inspection

@app.put("/inspections/{inspection_id}", response_model=InspectionOut)
def update_inspection(inspection_id: int, item: InspectionCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    inspection = db.query(Inspection).filter(Inspection.id == inspection_id).first()
    if not inspection:
        raise HTTPException(status_code=404, detail="Not found")
    inspection.facility_name = item.facility_name
    inspection.latitude = item.latitude
    inspection.longitude = item.longitude
    inspection.hvac_type = item.hvac_type
    # Update more fields as needed
    db.commit()
    db.refresh(inspection)
    return inspection

@app.delete("/inspections/{inspection_id}")
def delete_inspection(inspection_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    inspection = db.query(Inspection).filter(Inspection.id == inspection_id).first()
    if not inspection:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(inspection)
    db.commit()
    return {"status": "deleted"}
