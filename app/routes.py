from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from app.database import async_session
from app.models import User
from app.schemas import UserCreate, UserOut, UserLogin
from app.utils import get_password_hash, verify_password

router = APIRouter()

async def get_session() -> AsyncSession:
    async with async_session() as session:
        yield session

@router.post("/register", response_model=UserOut)
async def register_user(user: UserCreate, session: AsyncSession = Depends(get_session)):
    statment = select(User).where(User.username == user.username)
    result = await session.exec(statment)
    if result.first():
        return HTTPException(status_code=400, detail="Username already exists")
    
    new_user = User(username=user.username, hashed_password=get_password_hash(user.password))
    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)
    return new_user


@router.post("/login")
async def login_user(user: UserLogin, session: AsyncSession = Depends(get_session)):
    statment = select(User).where(User.username == user.username)
    result = await session.exec(statment)
    db_user = result.first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Login successful", "username": db_user.username}