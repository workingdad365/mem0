import datetime
from fastapi import FastAPI, APIRouter
from app.database import engine, Base, SessionLocal
from app.mcp_server import mcp # mcp_streamable_http is not used
from app.routers import memories_router, apps_router, stats_router, config_router
from starlette.responses import Response, RedirectResponse # Consolidated imports
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest # Renamed to avoid conflict if FastAPI's Request is used elsewhere with the same name
from fastapi_pagination import add_pagination
import logging # Added for ScopeDebugMiddleware logger
from fastapi.middleware.cors import CORSMiddleware
from app.models import User, App
from uuid import uuid4
from app.config import USER_ID, DEFAULT_APP_ID
from app.auth_middleware import AuthMiddleware # Added for JWT authentication

# FastMCP 앱 생성 시 서비스 경로를 '/' (루트)로 지정
# 이렇게 하면 FastMCP 앱은 마운트된 위치의 루트에서 요청을 처리함
http_app_from_mcp = mcp.http_app(path="/")

app = FastAPI(title="OpenMemory API", lifespan=http_app_from_mcp.lifespan)

# FastMCP 앱 내부 라우트 목록을 직접 출력 (디버깅용)
print("--- FastMCP App Internal Routes (raw list) ---")
print(http_app_from_mcp.routes)
print("--- End of FastMCP App Internal Routes (raw list) ---")

# FastAPI의 /mcp/ 경로 (후행 슬래시 포함)에 FastMCP 앱을 마운트
app.mount("/mcp/", http_app_from_mcp)

# Removed mcp_passthrough and mcp_slash_redirect as they conflict with the mount
# and are no longer needed with the simplified mounting strategy.

# Define ISSUER URL for AuthMiddleware
ISSUER = "https://openmemory.io/auth"

# Add AuthMiddleware first to handle JWT and set auth_claims
EXCLUDED_PATHS = ["/openapi.json", "/docs", "/redoc"]
app.add_middleware(
    AuthMiddleware,
    issuer_url=ISSUER,
    audience="openmemory-mcp-server",  # Use literal string for audience
    public_key_path="public_key.pem", # Path relative to main.py
    excluded_paths=EXCLUDED_PATHS
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create all tables
Base.metadata.create_all(bind=engine)

# Check for USER_ID and create default user if needed
def create_default_user():
    db = SessionLocal()
    try:
        # Check if user exists
        user = db.query(User).filter(User.user_id == USER_ID).first()
        if not user:
            # Create default user
            user = User(
                id=uuid4(),
                user_id=USER_ID,
                name="Default User",
                created_at=datetime.datetime.now(datetime.UTC)
            )
            db.add(user)
            db.commit()
    finally:
        db.close()


def create_default_app():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == USER_ID).first()
        if not user:
            return

        # Check if app already exists
        existing_app = db.query(App).filter(
            App.name == DEFAULT_APP_ID,
            App.owner_id == user.id
        ).first()

        if existing_app:
            return

        app = App(
            id=uuid4(),
            name=DEFAULT_APP_ID,
            owner_id=user.id,
            created_at=datetime.datetime.now(datetime.UTC),
            updated_at=datetime.datetime.now(datetime.UTC),
        )
        db.add(app)
        db.commit()
    finally:
        db.close()

# Create default user on startup
create_default_user()
create_default_app()

# Setup MCP server
#setup_mcp_server(app)

# Include routers
app.include_router(memories_router)
app.include_router(apps_router)
app.include_router(stats_router)
app.include_router(config_router)

# Add pagination support
add_pagination(app)
