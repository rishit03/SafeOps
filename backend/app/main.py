from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app import models
from app.routes import router
from app.scheduler import start_scheduler

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SafeOps API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://safeops-frontend.onrender.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.on_event("startup")
def startup_event():
    start_scheduler()


@app.get("/")
def root():
    return {"message": "SafeOps API running"}