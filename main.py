# Zoneium - Ultra-Simple Version for Render
import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import socketio
from datetime import datetime, timedelta
import uvicorn
import uuid
import motor.motor_asyncio
import bcrypt
import jwt

# Initialize FastAPI
app = FastAPI(title="Zoneium", version="3.0.0")

# CORS setup
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Simplified for now
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
db_client = None
database = None

# Socket.IO
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
socket_app = socketio.ASGIApp(sio, app)

# Simple password hashing
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, "secret-key", algorithm="HS256")

@app.on_event("startup")
async def startup():
    global db_client, database
    try:
        db_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)
        database = db_client.zoneium_production
        await db_client.admin.command('ping')
        print("✅ Database connected")
    except Exception as e:
        print(f"❌ Database error: {e}")

@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "version": "3.0.0",
        "domain": "zozenium.top"
    }

@app.post("/api/register")
async def register(request: Request):
    try:
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")
        
        if not all([username, password, email]):
            raise HTTPException(400, "Missing fields")
        
        # Check if user exists
        if database:
            existing = await database.users.find_one({"username": username})
            if existing:
                raise HTTPException(400, "User exists")
            
            # Create user
            user_doc = {
                "user_id": str(uuid.uuid4()),
                "username": username,
                "email": email,
                "password_hash": hash_password(password),
                "created_at": datetime.utcnow()
            }
            
            await database.users.insert_one(user_doc)
            token = create_token(username)
            
            return {
                "access_token": token,
                "user": {"username": username, "email": email}
            }
        
        return {"message": "Registration successful"}
        
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/login")
async def login(request: Request):
    try:
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
        
        if not all([username, password]):
            raise HTTPException(400, "Missing credentials")
        
        if database:
            user = await database.users.find_one({"username": username})
            if user and verify_password(password, user["password_hash"]):
                token = create_token(username)
                return {
                    "access_token": token,
                    "user": {"username": username, "email": user.get("email", "")}
                }
        
        raise HTTPException(401, "Invalid credentials")
        
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/")
async def root():
    return {
        "message": "🚀 Zoneium is running!",
        "version": "3.0.0",
        "domain": "zozenium.top"
    }

@sio.event
async def connect(sid, environ):
    print(f"Client {sid} connected")

@sio.event
async def disconnect(sid):
    print(f"Client {sid} disconnected")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(socket_app, host="0.0.0.0", port=port)
