from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, validator
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import pandas as pd
import io
import re

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# User Models
class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    confirm_email: str
    password: str
    
    @validator('email')
    def validate_email(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email format')
        return v.lower()
    
    @validator('confirm_email')
    def validate_confirm_email(cls, v, values):
        if 'email' in values and v != values['email']:
            raise ValueError('Email confirmation does not match')
        return v.lower()
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    first_name: str
    last_name: str
    email: str
    credits: int
    created_at: datetime

class PasswordChange(BaseModel):
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v

# Processing Models
class IMEIInput(BaseModel):
    imei: str
    
    @validator('imei')
    def validate_imei(cls, v):
        if not v.isdigit() or len(v) != 15:
            raise ValueError('IMEI must be exactly 15 digits')
        return v

class ProcessingRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    imei: str
    status: str = "new"  # new, processing, completed, failed
    request_number: Optional[str] = None
    response: Optional[str] = None
    batch_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ProcessingResponse(BaseModel):
    id: str
    imei: str
    status: str
    request_number: Optional[str]
    response: Optional[str]
    created_at: datetime
    updated_at: datetime

# Utility Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(user_id: str) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return UserResponse(**user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Authentication Routes
@api_router.post("/auth/signup")
async def signup(user_data: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create new user
    user_id = str(uuid.uuid4())
    user_dict = {
        "id": user_id,
        "first_name": user_data.first_name,
        "last_name": user_data.last_name,
        "email": user_data.email,
        "password_hash": hash_password(user_data.password),
        "credits": 100,  # Free 100 credits on signup
        "created_at": datetime.now(timezone.utc)
    }
    
    await db.users.insert_one(user_dict)
    
    # Create access token
    token = create_access_token(user_id)
    
    return {
        "message": "User created successfully",
        "token": token,
        "user": UserResponse(**user_dict)
    }

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    user = await db.users.find_one({"email": login_data.email.lower()})
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_access_token(user["id"])
    
    return {
        "message": "Login successful",
        "token": token,
        "user": UserResponse(**user)
    }

@api_router.get("/auth/me")
async def get_current_user_info(current_user: UserResponse = Depends(get_current_user)):
    return current_user

@api_router.post("/auth/change-password")
async def change_password(
    password_data: PasswordChange, 
    current_user: UserResponse = Depends(get_current_user)
):
    user = await db.users.find_one({"id": current_user.id})
    if not verify_password(password_data.current_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    new_password_hash = hash_password(password_data.new_password)
    await db.users.update_one(
        {"id": current_user.id},
        {"$set": {"password_hash": new_password_hash}}
    )
    
    return {"message": "Password changed successfully"}

# ATT Processing Routes
@api_router.post("/att/submit-imei")
async def submit_imei(
    imei_data: IMEIInput,
    current_user: UserResponse = Depends(get_current_user)
):
    # Check if user has credits
    if current_user.credits <= 0:
        raise HTTPException(status_code=400, detail="Insufficient credits")
    
    # Create processing request
    request_data = ProcessingRequest(
        user_id=current_user.id,
        imei=imei_data.imei
    )
    
    await db.processing_requests.insert_one(request_data.dict())
    
    # Deduct credit
    await db.users.update_one(
        {"id": current_user.id},
        {"$inc": {"credits": -1}}
    )
    
    return {"message": "IMEI submitted successfully", "request_id": request_data.id}

@api_router.post("/att/upload-file")
async def upload_file(
    file: UploadFile = File(...),
    current_user: UserResponse = Depends(get_current_user)
):
    if not file.filename.endswith(('.xlsx', '.xls', '.csv')):
        raise HTTPException(status_code=400, detail="File must be Excel or CSV format")
    
    try:
        contents = await file.read()
        
        if file.filename.endswith('.csv'):
            df = pd.read_csv(io.StringIO(contents.decode('utf-8')))
        else:
            df = pd.read_excel(io.BytesIO(contents))
        
        if 'IMEI' not in df.columns:
            raise HTTPException(status_code=400, detail="File must contain 'IMEI' column")
        
        imei_list = df['IMEI'].astype(str).tolist()
        
        # Validate IMEIs
        invalid_imeis = []
        for imei in imei_list:
            if not imei.isdigit() or len(imei) != 15:
                invalid_imeis.append(imei)
        
        if invalid_imeis:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid IMEIs found: {invalid_imeis[:10]}{'...' if len(invalid_imeis) > 10 else ''}"
            )
        
        # Check credits
        if current_user.credits < len(imei_list):
            raise HTTPException(
                status_code=400, 
                detail=f"Insufficient credits. Required: {len(imei_list)}, Available: {current_user.credits}"
            )
        
        # Create batch
        batch_id = str(uuid.uuid4())
        requests = []
        
        for imei in imei_list:
            request_data = ProcessingRequest(
                user_id=current_user.id,
                imei=imei,
                batch_id=batch_id
            )
            requests.append(request_data.dict())
        
        await db.processing_requests.insert_many(requests)
        
        # Deduct credits
        await db.users.update_one(
            {"id": current_user.id},
            {"$inc": {"credits": -len(imei_list)}}
        )
        
        return {
            "message": f"File uploaded successfully. {len(imei_list)} IMEIs processed.",
            "batch_id": batch_id,
            "total_requests": len(imei_list)
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing file: {str(e)}")

@api_router.get("/att/requests")
async def get_user_requests(current_user: UserResponse = Depends(get_current_user)):
    requests = await db.processing_requests.find(
        {"user_id": current_user.id}
    ).sort("created_at", -1).to_list(1000)
    
    return [ProcessingResponse(**req) for req in requests]

@api_router.get("/att/batch/{batch_id}")
async def get_batch_requests(
    batch_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    requests = await db.processing_requests.find(
        {"user_id": current_user.id, "batch_id": batch_id}
    ).sort("created_at", -1).to_list(1000)
    
    if not requests:
        raise HTTPException(status_code=404, detail="Batch not found")
    
    return [ProcessingResponse(**req) for req in requests]

@api_router.get("/att/download/{batch_id}")
async def download_batch_results(
    batch_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    requests = await db.processing_requests.find(
        {"user_id": current_user.id, "batch_id": batch_id}
    ).to_list(1000)
    
    if not requests:
        raise HTTPException(status_code=404, detail="Batch not found")
    
    # Create DataFrame
    data = []
    for req in requests:
        data.append({
            'IMEI': req['imei'],
            'Status': req['status'],
            'Request Number': req.get('request_number', ''),
            'Response': req.get('response', ''),
            'Created At': req['created_at'].isoformat(),
            'Updated At': req['updated_at'].isoformat()
        })
    
    df = pd.DataFrame(data)
    
    # Create Excel file in memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Results')
    
    output.seek(0)
    
    from fastapi.responses import StreamingResponse
    
    return StreamingResponse(
        io.BytesIO(output.read()),
        media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={"Content-Disposition": f"attachment; filename=batch_{batch_id}_results.xlsx"}
    )

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()