from fastapi import FastAPI
from app.routes import router
from app.database import init_db

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    await init_db()

app.include_router(router)