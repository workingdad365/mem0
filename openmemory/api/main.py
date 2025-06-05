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

# ScopeDebugMiddleware definition
scope_logger = logging.getLogger("scope_debug_middleware")
scope_logger.setLevel(logging.DEBUG)
# Ensure a handler is present if not configured globally by uvicorn already
if not scope_logger.handlers:
    scope_stream_handler = logging.StreamHandler()
    # More detailed format for scope logger, including timestamp
    scope_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    scope_stream_handler.setFormatter(scope_formatter)
    scope_logger.addHandler(scope_stream_handler)

class ScopeDebugMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        #scope_logger.info(f"SCOPE_DEBUG_MIDDLEWARE_ENTER: Path {request.url.path}") # New log
        
        #scope_logger.debug(f"Path: {request.url.path} - Scope dictionary content:")
        for key, value in request.scope.items():
            if key == "headers":
                decoded_headers = {k.decode('utf-8', 'ignore'): v.decode('utf-8', 'ignore') for k, v in value}
                #scope_logger.debug(f"Path: {request.url.path} -   {key}: {decoded_headers}")
            #elif key == "query_string" and isinstance(value, bytes):
                #scope_logger.debug(f"Path: {request.url.path} -   {key}: {value.decode('utf-8', 'ignore')}")
            #else:
                #scope_logger.debug(f"Path: {request.url.path} -   {key}: {value}")
        
        #if "auth_claims" in request.scope:
            #scope_logger.info(f"Path: {request.url.path} -   !!! auth_claims FOUND in scope: {request.scope['auth_claims']}")
        #else:
            #scope_logger.warning(f"Path: {request.url.path} -   !!! auth_claims NOT FOUND in scope.")
        
        response = await call_next(request)
        #scope_logger.info(f"SCOPE_DEBUG_MIDDLEWARE_EXIT: Path {request.url.path}") # New log
        return response
            


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

# Add ScopeDebugMiddleware *after* AuthMiddleware so it can log 'auth_claims'
app.add_middleware(ScopeDebugMiddleware)

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


# Include routers
app.include_router(memories_router)
app.include_router(apps_router)
app.include_router(stats_router)
app.include_router(config_router)

# Add pagination support
add_pagination(app)



# --- Logging registered routes on main app ---
import logging as main_logging # Use alias to avoid conflict if 'logging' is used differently above
main_logger = main_logging.getLogger("main_app_routes")
main_logger.setLevel(main_logging.INFO)

# Ensure a handler is present if not configured globally by uvicorn already
if not main_logger.handlers:
    stream_handler = main_logging.StreamHandler()
    formatter = main_logging.Formatter('%(levelname)s:     %(name)s - %(message)s')
    stream_handler.setFormatter(formatter)
    main_logger.addHandler(stream_handler)

main_logger.info("--- Registered routes on main FastAPI app ---")
for route_item in app.routes:
    path_info = getattr(route_item, "path", "N/A")
    name_info = getattr(route_item, "name", "N/A")
    methods_info = getattr(route_item, "methods", "N/A") # Relevant for APIRoute
    # For mounted applications, the route itself is the app
    if hasattr(route_item, "app") and not isinstance(route_item, APIRouter):
        # This could be a Mount instance
        main_logger.info(f"App route (Mount): Path='{path_info}', Name='{name_info}', App='{type(getattr(route_item, 'app', None)).__name__}'")
    elif hasattr(route_item, "endpoint") : # Standard APIRoute
         main_logger.info(f"App route (APIRoute): Path='{path_info}', Name='{name_info}', Methods={methods_info}, Endpoint='{getattr(route_item, 'endpoint', None).__name__}'")
    else:
        main_logger.info(f"App route (Other): Type='{type(route_item).__name__}', Path='{path_info}', Name='{name_info}'")
main_logger.info("--- End of registered routes on main FastAPI app ---")
# --- End of logging ---
