from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
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
import asyncpg
import asyncio
from contextlib import asynccontextmanager

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# PostgreSQL Configuration
DATABASE_URL = os.environ.get('DATABASE_URL')

# Database connection pool
db_pool = None

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

class ProcessingResponse(BaseModel):
    id: str
    imei: str
    status: str
    request_number: Optional[str]
    response: Optional[str]
    created_at: datetime
    updated_at: datetime

# Database initialization
async def init_database():
    """Initialize database tables"""
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=10)
    
    async with db_pool.acquire() as conn:
        # Create users table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                first_name VARCHAR(100) NOT NULL,
                last_name VARCHAR(100) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                credits INTEGER DEFAULT 100,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        ''')
        
        # Create processing_requests table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS processing_requests (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                imei VARCHAR(15) NOT NULL,
                status VARCHAR(20) DEFAULT 'new',
                request_number VARCHAR(100),
                response TEXT,
                batch_id UUID,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        ''')
        
        # Create indexes for better performance
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_processing_requests_user_id ON processing_requests(user_id)')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_processing_requests_status ON processing_requests(status)')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_processing_requests_batch_id ON processing_requests(batch_id)')

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
        
        async with db_pool.acquire() as conn:
            user = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
        
        return UserResponse(
            id=str(user['id']),
            first_name=user['first_name'],
            last_name=user['last_name'],
            email=user['email'],
            credits=user['credits'],
            created_at=user['created_at']
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# FastAPI app with lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_database()
    yield
    # Shutdown
    if db_pool:
        await db_pool.close()

app = FastAPI(lifespan=lifespan)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Authentication Routes
@api_router.post("/auth/signup")
async def signup(user_data: UserCreate):
    async with db_pool.acquire() as conn:
        # Check if user already exists
        existing_user = await conn.fetchrow("SELECT id FROM users WHERE email = $1", user_data.email)
        if existing_user:
            raise HTTPException(status_code=400, detail="User already exists")
        
        # Create new user
        user_id = await conn.fetchval('''
            INSERT INTO users (first_name, last_name, email, password_hash, credits)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
        ''', user_data.first_name, user_data.last_name, user_data.email, 
            hash_password(user_data.password), 100)
        
        # Get the created user
        user = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
        
        # Create access token
        token = create_access_token(str(user_id))
        
        return {
            "message": "User created successfully",
            "token": token,
            "user": UserResponse(
                id=str(user['id']),
                first_name=user['first_name'],
                last_name=user['last_name'],
                email=user['email'],
                credits=user['credits'],
                created_at=user['created_at']
            )
        }

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("SELECT * FROM users WHERE email = $1", login_data.email.lower())
        if not user or not verify_password(login_data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        token = create_access_token(str(user["id"]))
        
        return {
            "message": "Login successful",
            "token": token,
            "user": UserResponse(
                id=str(user['id']),
                first_name=user['first_name'],
                last_name=user['last_name'],
                email=user['email'],
                credits=user['credits'],
                created_at=user['created_at']
            )
        }

@api_router.get("/auth/me")
async def get_current_user_info(current_user: UserResponse = Depends(get_current_user)):
    return current_user

@api_router.post("/auth/change-password")
async def change_password(
    password_data: PasswordChange, 
    current_user: UserResponse = Depends(get_current_user)
):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("SELECT password_hash FROM users WHERE id = $1", current_user.id)
        if not verify_password(password_data.current_password, user["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        
        new_password_hash = hash_password(password_data.new_password)
        await conn.execute(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            new_password_hash, current_user.id
        )
        
        return {"message": "Password changed successfully"}

# ATT Processing Routes
@api_router.post("/att/submit-imei")
async def submit_imei(
    imei_data: IMEIInput,
    current_user: UserResponse = Depends(get_current_user)
):
    async with db_pool.acquire() as conn:
        # Check if user has credits
        user = await conn.fetchrow("SELECT credits FROM users WHERE id = $1", current_user.id)
        if user['credits'] <= 0:
            raise HTTPException(status_code=400, detail="Insufficient credits")
        
        # Create processing request
        request_id = await conn.fetchval('''
            INSERT INTO processing_requests (user_id, imei, status)
            VALUES ($1, $2, 'new')
            RETURNING id
        ''', current_user.id, imei_data.imei)
        
        # Deduct credit
        await conn.execute(
            "UPDATE users SET credits = credits - 1 WHERE id = $1",
            current_user.id
        )
        
        return {"message": "IMEI submitted successfully", "request_id": str(request_id)}

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
        
        async with db_pool.acquire() as conn:
            # Check credits
            user = await conn.fetchrow("SELECT credits FROM users WHERE id = $1", current_user.id)
            if user['credits'] < len(imei_list):
                raise HTTPException(
                    status_code=400, 
                    detail=f"Insufficient credits. Required: {len(imei_list)}, Available: {user['credits']}"
                )
            
            # Create batch
            batch_id = str(uuid.uuid4())
            
            # Insert all requests in a transaction
            async with conn.transaction():
                for imei in imei_list:
                    await conn.execute('''
                        INSERT INTO processing_requests (user_id, imei, status, batch_id)
                        VALUES ($1, $2, 'new', $3)
                    ''', current_user.id, imei, batch_id)
                
                # Deduct credits
                await conn.execute(
                    "UPDATE users SET credits = credits - $1 WHERE id = $2",
                    len(imei_list), current_user.id
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
    async with db_pool.acquire() as conn:
        requests = await conn.fetch('''
            SELECT * FROM processing_requests 
            WHERE user_id = $1 
            ORDER BY created_at DESC 
            LIMIT 1000
        ''', current_user.id)
        
        return [ProcessingResponse(
            id=str(req['id']),
            imei=req['imei'],
            status=req['status'],
            request_number=req['request_number'],
            response=req['response'],
            created_at=req['created_at'],
            updated_at=req['updated_at']
        ) for req in requests]

@api_router.get("/att/batch/{batch_id}")
async def get_batch_requests(
    batch_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    async with db_pool.acquire() as conn:
        requests = await conn.fetch('''
            SELECT * FROM processing_requests 
            WHERE user_id = $1 AND batch_id = $2 
            ORDER BY created_at DESC
        ''', current_user.id, batch_id)
        
        if not requests:
            raise HTTPException(status_code=404, detail="Batch not found")
        
        return [ProcessingResponse(
            id=str(req['id']),
            imei=req['imei'],
            status=req['status'],
            request_number=req['request_number'],
            response=req['response'],
            created_at=req['created_at'],
            updated_at=req['updated_at']
        ) for req in requests]

@api_router.get("/att/download/{batch_id}")
async def download_batch_results(
    batch_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    async with db_pool.acquire() as conn:
        requests = await conn.fetch('''
            SELECT * FROM processing_requests 
            WHERE user_id = $1 AND batch_id = $2
        ''', current_user.id, batch_id)
        
        if not requests:
            raise HTTPException(status_code=404, detail="Batch not found")
        
        # Create DataFrame
        data = []
        for req in requests:
            data.append({
                'IMEI': req['imei'],
                'Status': req['status'],
                'Request Number': req['request_number'] or '',
                'Response': req['response'] or '',
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