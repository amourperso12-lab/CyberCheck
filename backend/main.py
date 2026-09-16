from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from backend.security import analyze_password_strength
from backend.scanner import check_email_leak, check_ip_reputation
import os

app = FastAPI(title="CYBERCHECK API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PasswordRequest(BaseModel):
    password: str

class EmailRequest(BaseModel):
    email: str

class IPRequest(BaseModel):
    ip: str

@app.post("/api/check-password")
def api_check_password(req: PasswordRequest):
    return analyze_password_strength(req.password)

@app.post("/api/check-email")
def api_check_email(req: EmailRequest):
    return check_email_leak(req.email)

@app.post("/api/check-ip")
def api_check_ip(req: IPRequest):
    return check_ip_reputation(req.ip)

# Monte le front-end statique
frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend"))
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
