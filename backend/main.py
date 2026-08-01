from fastapi import FastAPI
from db import engine, Base
from models.scan import Scan
from routers import scan
from models.history import ScanHistory
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


Base.metadata.create_all(bind=engine)


app.include_router(
    scan.router,
    prefix="/api"
)


@app.get("/")
def home():
    return {
        "message": "PhishGuard running"
    }