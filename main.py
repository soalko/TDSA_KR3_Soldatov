import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List

import jwt
from jwt import PyJWTError
import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from pydantic import field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import Column, Integer, String, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
MODE = os.getenv("MODE", "DEV").upper()
DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "secret")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

if MODE not in ("DEV", "PROD"):
    raise ValueError("MODE must be either DEV or PROD")

SQLALCHEMY_DATABASE_URL = "sqlite:///./app.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")  # admin, user, guest

class TodoDB(Base):
    __tablename__ = "todos"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    completed = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    role: Optional[str] = "user"

    @field_validator('password')
    def validate_password_length(cls, v):
        if len(v.encode('utf-8')) > 72:
            logger.warning("Password exceeds 72 bytes, will be truncated for bcrypt")
        return v


class UserInDB(UserBase):
    hashed_password: str
    role: str

class UserResponse(UserBase):
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginJSON(BaseModel):
    username: str
    password: str

class TodoBase(BaseModel):
    title: str
    description: Optional[str] = None

class TodoCreate(TodoBase):
    pass

class TodoUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    completed: Optional[bool] = None

class TodoResponse(TodoBase):
    id: int
    completed: bool

    class Config:
        from_attributes = True

security_basic = HTTPBasic()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля с использованием bcrypt напрямую"""
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8') if isinstance(hashed_password, str) else hashed_password
        )
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Хеширование пароля с использованием bcrypt напрямую"""
    # Ограничение bcrypt - 72 байта
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]

    # Генерируем соль и хешируем
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)

    # Возвращаем как строку (для хранения в БД)
    return hashed.decode('utf-8') if isinstance(hashed, bytes) else hashed

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except PyJWTError:  # используйте импортированный PyJWTError
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user_by_username(db: Session, username: str) -> Optional[UserDB]:
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user and secrets.compare_digest(user.username, username):
        return user
    return None

def authenticate_user(db: Session, username: str, password: str) -> Optional[UserDB]:
    user = get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def auth_user_basic(
    credentials: HTTPBasicCredentials = Depends(security_basic),
    db: Session = Depends(get_db),
) -> UserDB:
    user = authenticate_user(db, credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user

def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> UserDB:
    payload = decode_token(token)
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = get_user_by_username(db, username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def require_role(required_roles: List[str]):
    def role_checker(current_user: UserDB = Depends(get_current_user)):
        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {current_user.role} not allowed. Required: {required_roles}",
            )
        return current_user
    return role_checker


app = FastAPI(
    title="Combined FastAPI App",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def docs_auth_dependency(credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
    correct_username = secrets.compare_digest(credentials.username, DOCS_USER)
    correct_password = secrets.compare_digest(credentials.password, DOCS_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid documentation credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

if MODE == "DEV":
    @app.get("/docs", include_in_schema=False, dependencies=[Depends(docs_auth_dependency)])
    async def custom_swagger_ui_html():
        return get_swagger_ui_html(openapi_url="/openapi.json", title=app.title)

    @app.get("/openapi.json", include_in_schema=False, dependencies=[Depends(docs_auth_dependency)])
    async def custom_openapi():
        return JSONResponse(get_openapi(title=app.title, version=app.version, routes=app.routes))
else:
    @app.get("/docs", include_in_schema=False)
    @app.get("/redoc", include_in_schema=False)
    @app.get("/openapi.json", include_in_schema=False)
    async def docs_not_found():
        raise HTTPException(status_code=404, detail="Not Found")


@app.get("/basic-secret")
def get_secret_with_basic_auth(user: UserDB = Depends(auth_user_basic)):
    return {"message": "You got my secret, welcome"}

@app.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("1/minute")
def register_user(
    request: Request,
    user_data: UserCreate,
    db: Session = Depends(get_db),
):
    existing = get_user_by_username(db, user_data.username)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists",
        )
    if user_data.role not in ("user", "guest"):
        user_data.role = "user"
    hashed = get_password_hash(user_data.password)
    new_user = UserDB(
        username=user_data.username,
        hashed_password=hashed,
        role=user_data.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "New user created"}

@app.get("/basic-login")
def basic_login_greeting(user: UserDB = Depends(auth_user_basic)):
    return {"message": f"Welcome, {user.username}!"}

@app.post("/login", response_model=Token)
@limiter.limit("5/minute")
def login_for_access_token(
    request: Request,
    credentials: LoginJSON,
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, credentials.username, credentials.password)
    if not user:
        existing = get_user_by_username(db, credentials.username)
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization failed",
                headers={"WWW-Authenticate": "Bearer"},
            )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected_resource")
def protected_resource(current_user: UserDB = Depends(get_current_user)):
    return {"message": "Access granted"}

@app.get("/admin-only")
def admin_endpoint(_: UserDB = Depends(require_role(["admin"]))):
    return {"message": "Hello Admin! You have full access."}

@app.get("/user-or-admin")
def user_or_admin_endpoint(_: UserDB = Depends(require_role(["user", "admin"]))):
    return {"message": "Hello User or Admin! You can read and update."}

@app.get("/guest-allowed")
def guest_allowed_endpoint(_: UserDB = Depends(require_role(["guest", "user", "admin"]))):
    return {"message": "Hello Guest! Read-only access."}

@app.post("/todos", response_model=TodoResponse, status_code=status.HTTP_201_CREATED)
def create_todo(
    todo: TodoCreate,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(get_current_user),
):
    db_todo = TodoDB(**todo.model_dump())
    db.add(db_todo)
    db.commit()
    db.refresh(db_todo)
    return db_todo

@app.get("/todos/{todo_id}", response_model=TodoResponse)
def read_todo(
    todo_id: int,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(get_current_user),
):
    todo = db.query(TodoDB).filter(TodoDB.id == todo_id).first()
    if not todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    return todo

@app.put("/todos/{todo_id}", response_model=TodoResponse)
def update_todo(
    todo_id: int,
    todo_update: TodoUpdate,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(get_current_user),
):
    todo = db.query(TodoDB).filter(TodoDB.id == todo_id).first()
    if not todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    update_data = todo_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(todo, field, value)
    db.commit()
    db.refresh(todo)
    return todo

@app.delete("/todos/{todo_id}")
def delete_todo(
    todo_id: int,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(require_role(["admin"])),
):
    todo = db.query(TodoDB).filter(TodoDB.id == todo_id).first()
    if not todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    db.delete(todo)
    db.commit()
    return {"message": f"Todo {todo_id} deleted"}

@app.get("/")
def root():
    return {"status": "ok", "mode": MODE}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)