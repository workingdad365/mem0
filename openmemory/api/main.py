import datetime
from fastapi import FastAPI, APIRouter
from app.database import engine, Base, SessionLocal
from app.mcp_server import mcp # mcp_streamable_http is not used
from app.routers import memories_router, apps_router, stats_router, config_router
from starlette.responses import Response, RedirectResponse # Consolidated imports
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi_pagination import add_pagination
from fastapi.middleware.cors import CORSMiddleware
from app.models import User, App
from uuid import uuid4
from app.config import USER_ID, DEFAULT_APP_ID

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

from fastapi import Request

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
