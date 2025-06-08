"""
MCP Server for OpenMemory with resilient memory client handling.

This module implements an MCP (Model Context Protocol) server that provides
memory operations for OpenMemory. The memory client is initialized lazily
to prevent server crashes when external dependencies (like Ollama) are
unavailable. If the memory client cannot be initialized, the server will
continue running with limited functionality and appropriate error messages.

Key features:
- Lazy memory client initialization
- Graceful error handling for unavailable dependencies
- Fallback to database-only mode when vector store is unavailable
- Proper logging for debugging connection issues
- Environment variable parsing for API keys
"""

import logging
import json
from typing import List, Dict, Any, Union
from fastmcp import FastMCP, Context
from fastmcp.server.auth import BearerAuthProvider
from fastmcp.server.dependencies import get_access_token, AccessToken

from app.utils.memory import get_memory_client
from fastapi import FastAPI, Request, Response, HTTPException, Depends, Security
from starlette.types import Scope, Receive, Send
from starlette.responses import JSONResponse
from fastapi.routing import APIRouter
import logging
import json
import contextvars
import os
from dotenv import load_dotenv
from app.database import SessionLocal
from app.models import Memory, MemoryState, MemoryStatusHistory, MemoryAccessLog
from app.utils.db import get_user_and_app
import uuid
import datetime
from app.utils.permissions import check_memory_access_permissions
from qdrant_client import models as qdrant_models
from pathlib import Path # 추가
from typing import Any # 추가 for MCPUserContext pydantic compatibility
from pydantic_core import core_schema # 추가 for MCPUserContext pydantic compatibility
from fastmcp.server.server import FastMCP # fastmcp.server.server 모듈에서 FastMCP 클래스를 가져옴
from contextlib import asynccontextmanager # 추가
from typing import AsyncIterator # 추가
from fastapi import status # 추가 for status codes
from fastapi.security import HTTPBearer # 추가

# Load environment variables
load_dotenv()

# 공개키 파일 경로 (create_token.py와 동일 위치)
# __file__ 은 현재 파일(mcp_server.py)의 경로를 나타냅니다.
# .parent는 app 디렉토리, .parent.parent는 api 디렉토리를 가리킵니다.
PUBLIC_KEY_FILE = Path(__file__).resolve().parent.parent / "public_key.pem"

# Load public key from file
RSA_PUBLIC_KEY = ""
if PUBLIC_KEY_FILE.exists():
    try:
        RSA_PUBLIC_KEY = PUBLIC_KEY_FILE.read_text()
        if not RSA_PUBLIC_KEY.strip():
            logging.error(f"Public key file {PUBLIC_KEY_FILE} is empty. Server cannot start without a public key.")
            raise ValueError(f"Public key file {PUBLIC_KEY_FILE} is empty.")
        logging.info(f"Successfully loaded public key from {PUBLIC_KEY_FILE}")
    except Exception as e:
        logging.error(f"Error loading public key from {PUBLIC_KEY_FILE}: {e}. Server cannot start.")
        raise RuntimeError(f"Error loading public key from {PUBLIC_KEY_FILE}: {e}")
else:
    logging.error(f"Public key file not found at {PUBLIC_KEY_FILE}. Please run create_token.py first. Server cannot start.")
    raise FileNotFoundError(
        f"Public key file not found at {PUBLIC_KEY_FILE}. "
        "Please run create_token.py first to generate the key pair."
    )

# FastMCP Server Initialization with Bearer Authentication
mcp = FastMCP( # FastMCP 클래스 사용
    title="OpenMemory MCP Server",
    description="MCP Server for OpenMemory with JWT Bearer Token Authentication",
    version="1.0.0",
    auth_providers=[
        BearerAuthProvider(
            public_key=RSA_PUBLIC_KEY, # 파일에서 읽어온 공개키 사용
            issuer="https://openmemory.io/auth", # create_token.py와 일치해야 함
            audience="openmemory-mcp-server",    # create_token.py와 일치해야 함
        )
    ],
    # context_vars를 여기에 직접 전달할 필요는 없습니다.
    # MCPUserContext와 mcp_user_context_dependency가 이를 처리합니다.
)

# Don't initialize memory client at import time - do it lazily when needed
def get_memory_client_safe():
    """Get memory client with error handling. Returns None if client cannot be initialized."""
    try:
        return get_memory_client()
    except Exception as e:
        logging.warning(f"Failed to get memory client: {e}")
        return None

# Context variables for user_id and client_name
user_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("user_id", default=None)
client_name_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("client_name", default=None)

# 로거 설정 - 핸들러 중복 방지
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# 기존 핸들러 제거 (중복 방지)
for handler in logger.handlers[:]: 
    logger.removeHandler(handler)
# 새 핸들러 추가
stream_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
# 로그 전파 방지 (부모 로거로 전파되지 않도록 설정)
logger.propagate = False

@mcp.tool(description="Add a new memory. This method is called everytime the user informs anything about themselves, their preferences, or anything that has any relevant information which can be useful in the future conversation. This can also be called when the user asks you to remember something.")
async def add_memories(ctx: Context, text: str) -> dict[str, Any]:
    user_id_token = None
    client_name_token = None
    uid_for_logging = "unknown_user"
    logger.info("----------------------------------------------------------------------")
    logger.info(f"[MCP INFO] add_memories: Attempting to access auth_claims from context.")
    
    # 인증 정보 가져오기
    auth_claims = None
    auth_source = None
    
    try:
        request = ctx.get_http_request()
        if request and 'auth_claims' in request.scope:
            auth_claims = request.scope['auth_claims']
            auth_source = "request.scope['auth_claims']"
            logger.info(f"[MCP DEBUG] Found auth_claims in request.scope: {auth_claims}")
    except Exception as e:
        logger.debug(f"[MCP DEBUG] Could not access request.scope['auth_claims']: {e}")
   
    
    # 인증 정보 확인
    if auth_claims:
        logger.info(f"[MCP INFO] Successfully retrieved auth_claims via {auth_source}: {auth_claims}")
    else:
        logger.error("[MCP ERROR] Failed to retrieve auth_claims through any method")
        raise HTTPException(status_code=401, detail="Authentication failed: Could not retrieve auth claims")

    if auth_claims:
        user_id_token = auth_claims.get("sub")
        # MCP Inspector는 client_name 클레임을 보내지 않을 수 있으므로 기본값을 사용합니다.
        client_name_token = auth_claims.get("client_name", "mcp_inspector_client") 
        uid_for_logging = f"{client_name_token}:{user_id_token}"
        logger.info(f"[MCP INFO] add_memories: User '{uid_for_logging}' attempting to add memory.")
        logger.info(f"[MCP INFO] add_memories: Full auth_claims: {json.dumps(auth_claims, indent=4)}")
    else:
        logger.warning("[MCP WARNING] add_memories: ctx.auth_claims is None. Cannot identify user or retrieve claims.")
        # 인증이 필요한 경우 여기서 접근을 거부하거나 예외를 발생시킬 수 있습니다.
        # 예: raise HTTPException(status_code=401, detail="Authentication required for add_memories")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication claims not found in context.")

    if not user_id_token:
        logger.error(f"[MCP ERROR] add_memories: 'sub' (User ID) not found in auth_claims. Cannot proceed.")
        # 이 경우는 auth_claims는 있었지만 'sub'이 없는 경우입니다.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User ID ('sub') not found in token claims.")
    
    # 메모리 클라이언트 가져오기
    memory_client = get_memory_client_safe()
    if not memory_client:
        logger.error(f"[MCP ERROR] add_memories: Memory system is unavailable for user '{uid_for_logging}'")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Memory system is currently unavailable. Please try again later.")
    
    try:
        db = SessionLocal()
        try:
            # 사용자 및 앱 정보 가져오기
            user, app = get_user_and_app(db, user_id=user_id_token, app_id=client_name_token)
            
            # 앱이 활성 상태인지 확인
            if not app.is_active:
                logger.error(f"[MCP ERROR] add_memories: App {app.name} is paused for user '{uid_for_logging}'")
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                                   detail=f"App {app.name} is currently paused on OpenMemory. Cannot create new memories.")
            
            # 메모리 추가
            response = memory_client.add(text,
                                       user_id=user_id_token,
                                       metadata={
                                          "source_app": "openmemory",
                                          "mcp_client": client_name_token,
                                      })
            
            # 응답 처리 및 데이터베이스 업데이트
            if isinstance(response, dict) and 'results' in response:
                for result in response['results']:
                    memory_id = uuid.UUID(result['id'])
                    memory = db.query(Memory).filter(Memory.id == memory_id).first()

                    if result['event'] == 'ADD':
                        if not memory:
                            memory = Memory(
                                id=memory_id,
                                user_id=user.id,
                                app_id=app.id,
                                content=result['memory'],
                                state=MemoryState.active
                            )
                            db.add(memory)
                        else:
                            memory.state = MemoryState.active
                            memory.content = result['memory']

                        # 기록 생성
                        history = MemoryStatusHistory(
                            memory_id=memory_id,
                            changed_by=user.id,
                            old_state=MemoryState.deleted if memory else None,
                            new_state=MemoryState.active
                        )
                        db.add(history)

                    elif result['event'] == 'DELETE':
                        if memory:
                            memory.state = MemoryState.deleted
                            memory.deleted_at = datetime.datetime.now(datetime.UTC)
                            # 기록 생성
                            history = MemoryStatusHistory(
                                memory_id=memory_id,
                                changed_by=user.id,
                                old_state=MemoryState.active,
                                new_state=MemoryState.deleted
                            )
                            db.add(history)

                db.commit()
            
            logger.info(f"Memory added for user {uid_for_logging}: {text[:50]}...")
            logger.info("----------------------------------------------------------------------")
            return response
        finally:
            db.close()
    except HTTPException as http_exc:
        # HTTP 예외는 그대로 전달
        logger.info("----------------------------------------------------------------------")
        raise http_exc
    except Exception as e:
        logger.error(f"[MCP ERROR] add_memories: Error adding memory for user '{uid_for_logging}': {e}", exc_info=True)
        logger.info("----------------------------------------------------------------------")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error adding to memory: {str(e)}")

@mcp.tool(description="Search for memories based on a query string. This is useful for retrieving past information or context.")
async def search_memory(ctx: Context, query: str, top_k: int = 5) -> dict[str, Any]:
    user_id_token = None
    client_name_token = None
    uid_for_logging = "unknown_user"
    logger.info("----------------------------------------------------------------------")
    logger.info(f"[MCP INFO] search_memory: Attempting to access auth_claims from context.")
    
    # 인증 정보 가져오기
    auth_claims = None
    auth_source = None
 
    try:
        request = ctx.get_http_request()
        if request and 'auth_claims' in request.scope:
            auth_claims = request.scope['auth_claims']
            auth_source = "request.scope['auth_claims']"
            logger.info(f"[MCP DEBUG] Found auth_claims via request.scope['auth_claims']: {auth_claims}")
    except Exception as e_scope:
        logger.debug(f"[MCP DEBUG] Could not access request.scope['auth_claims']: {e_scope}")
    
    if auth_claims:
        user_id_token = auth_claims.get("sub")
        client_name_token = auth_claims.get("client_name", "mcp_inspector_client")
        uid_for_logging = f"{client_name_token}:{user_id_token}"
        logger.info(f"[MCP INFO] search_memory: User '{uid_for_logging}' searching for memory via {auth_source}.")
        logger.info(f"[MCP INFO] search_memory: Full auth_claims: {json.dumps(auth_claims, indent=4)}")
    else:
        logger.warning("[MCP WARNING] search_memory: Failed to retrieve auth_claims from any source. Cannot identify user.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication claims not found in context.")

    if not user_id_token:
        logger.error(f"[MCP ERROR] search_memory: 'sub' (User ID) not found in auth_claims for search_memory. Claims: {auth_claims}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User ID ('sub') missing from token claims.")

    logger.info(f"search_memory called by user {uid_for_logging} with query: '{query}', top_k: {top_k}")

    # 메모리 클라이언트 가져오기
    memory_client = get_memory_client_safe()
    if not memory_client:
        logger.error(f"[MCP ERROR] search_memory: Memory system is unavailable for user '{uid_for_logging}'")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Memory system is currently unavailable. Please try again later.")
    
    try:
        db = SessionLocal()
        try:
            # 사용자 및 앱 정보 가져오기
            user, app = get_user_and_app(db, user_id=user_id_token, app_id=client_name_token)
            
            # 앱이 활성 상태인지 확인
            if not app.is_active:
                logger.error(f"[MCP ERROR] search_memory: App {app.name} is paused for user '{uid_for_logging}'")
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                                   detail=f"App {app.name} is currently paused on OpenMemory. Cannot search memories.")
            
            # 접근 가능한 메모리 ID 가져오기
            user_memories = db.query(Memory).filter(Memory.user_id == user.id).all()
            accessible_memory_ids = [memory.id for memory in user_memories if check_memory_access_permissions(db, memory, app.id)]
            
            try:
                # Qdrant 필터 조건 설정
                conditions = [qdrant_models.FieldCondition(key="user_id", match=qdrant_models.MatchValue(value=user_id_token))]
                
                if accessible_memory_ids:
                    # UUID를 문자열로 변환하여 Qdrant에서 사용
                    accessible_memory_ids_str = [str(memory_id) for memory_id in accessible_memory_ids]
                    conditions.append(qdrant_models.HasIdCondition(has_id=accessible_memory_ids_str))

                filters = qdrant_models.Filter(must=conditions)
                embeddings = memory_client.embedding_model.embed(query, "search")
                
                # 벡터 검색 실행
                hits = memory_client.vector_store.client.query_points(
                    collection_name=memory_client.vector_store.collection_name,
                    query=embeddings,
                    query_filter=filters,
                    limit=top_k,
                )

                # 검색 결과 처리
                memories = hits.points
                memories = [
                    {
                        "id": memory.id,
                        "memory": memory.payload["data"],
                        "hash": memory.payload.get("hash"),
                        "created_at": memory.payload.get("created_at"),
                        "updated_at": memory.payload.get("updated_at"),
                        "score": memory.score,
                    }
                    for memory in memories
                ]

                # 메모리 접근 로그 생성
                for memory in memories:
                    memory_id = uuid.UUID(memory['id'])
                    # 접근 로그 생성
                    access_log = MemoryAccessLog(
                        memory_id=memory_id,
                        app_id=app.id,
                        access_type="search",
                        metadata_={
                            "query": query,
                            "score": memory.get('score'),
                            "hash": memory.get('hash')
                        }
                    )
                    db.add(access_log)
                db.commit()
                
                logger.info(f"Search for '{query}' by user {uid_for_logging} returned {len(memories)} results.")
                logger.info("----------------------------------------------------------------------")
                return {"status": "success", "results": memories}
                
            except Exception as vector_error:
                logger.error(f"[MCP ERROR] search_memory: Vector search error for user '{uid_for_logging}': {vector_error}", exc_info=True)
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                                   detail=f"Vector search error: {str(vector_error)}")
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[MCP ERROR] search_memory: Error searching memories for user '{uid_for_logging}': {e}", exc_info=True)
        logger.info("----------------------------------------------------------------------")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error searching memories: {str(e)}")

@mcp.tool(description="List all memories for the current user. Useful for browsing or reviewing stored information.")
async def list_memories(ctx: Context, page: int = 1, page_size: int = 10) -> dict[str, Any]:
    user_id_token = None
    client_name_token = None
    uid_for_logging = "unknown_user"
    logger.info("----------------------------------------------------------------------")
    logger.info(f"[MCP INFO] list_memories: Attempting to access auth_claims from context.")
    
    # 인증 정보 가져오기
    auth_claims = None
    auth_source = None
    
    try:
        request = ctx.get_http_request()
        if request and 'auth_claims' in request.scope:
            auth_claims = request.scope['auth_claims']
            auth_source = "request.scope['auth_claims']"
            logger.info(f"[MCP DEBUG] Found auth_claims in request.scope: {auth_claims}")
    except Exception as e_scope:
        logger.debug(f"[MCP DEBUG] Could not access request.scope['auth_claims']: {e_scope}")

    # 인증 정보 확인
    if auth_claims:
        logger.info(f"[MCP INFO] Successfully retrieved auth_claims via {auth_source}: {auth_claims}")
    else:
        logger.error("[MCP ERROR] Failed to retrieve auth_claims through any method")
        raise HTTPException(status_code=401, detail="Authentication failed: Could not retrieve auth claims")

    if auth_claims:
        user_id_token = auth_claims.get("sub")
        client_name_token = auth_claims.get("client_name", "mcp_inspector_client")
        uid_for_logging = f"{client_name_token}:{user_id_token}"
        logger.info(f"[MCP INFO] list_memories: User '{uid_for_logging}' listing memories via {auth_source}.")
        logger.info(f"[MCP INFO] list_memories: Full auth_claims: {json.dumps(auth_claims, indent=4)}")
    else:
        logger.warning("[MCP WARNING] list_memories: Failed to retrieve auth_claims from any source. Cannot identify user.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication claims not found in context.")

    if not user_id_token:
        logger.error(f"[MCP ERROR] list_memories: 'sub' (User ID) not found in auth_claims. Claims: {auth_claims}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User ID ('sub') missing from token claims.")

    logger.info(f"list_memories called by user {uid_for_logging} with page: {page}, page_size: {page_size}")

    # 메모리 클라이언트 가져오기
    memory_client = get_memory_client_safe()
    if not memory_client:
        logger.error(f"[MCP ERROR] list_memories: Memory system is unavailable for user '{uid_for_logging}'")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Memory system is currently unavailable. Please try again later.")
    
    try:
        db = SessionLocal()
        try:
            # 사용자 및 앱 정보 가져오기
            user, app = get_user_and_app(db, user_id=user_id_token, app_id=client_name_token)
            
            # 앱이 활성 상태인지 확인
            if not app.is_active:
                logger.error(f"[MCP ERROR] list_memories: App {app.name} is paused for user '{uid_for_logging}'")
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                                   detail=f"App {app.name} is currently paused on OpenMemory. Cannot list memories.")
            
            # 메모리 가져오기
            memories = memory_client.get_all(user_id=user_id_token)
            filtered_memories = []
            
            # 권한에 따라 메모리 필터링
            user_memories = db.query(Memory).filter(Memory.user_id == user.id).all()
            accessible_memory_ids = [memory.id for memory in user_memories if check_memory_access_permissions(db, memory, app.id)]
            
            # 페이지네이션 처리
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            
            # 메모리 데이터 처리
            if isinstance(memories, dict) and 'results' in memories:
                for memory_data in memories['results']:
                    if 'id' in memory_data:
                        memory_id = uuid.UUID(memory_data['id'])
                        if memory_id in accessible_memory_ids:
                            # 접근 로그 생성
                            access_log = MemoryAccessLog(
                                memory_id=memory_id,
                                app_id=app.id,
                                access_type="list",
                                metadata_={
                                    "hash": memory_data.get('hash')
                                }
                            )
                            db.add(access_log)
                            filtered_memories.append(memory_data)
                db.commit()
            else:
                for memory in memories:
                    memory_id = uuid.UUID(memory['id'])
                    memory_obj = db.query(Memory).filter(Memory.id == memory_id).first()
                    if memory_obj and check_memory_access_permissions(db, memory_obj, app.id):
                        # 접근 로그 생성
                        access_log = MemoryAccessLog(
                            memory_id=memory_id,
                            app_id=app.id,
                            access_type="list",
                            metadata_={
                                "hash": memory.get('hash')
                            }
                        )
                        db.add(access_log)
                        filtered_memories.append(memory)
                db.commit()
            
            # 페이지네이션 정보 계산
            total_memories = len(filtered_memories)
            paginated_memories = filtered_memories[start_idx:end_idx] if start_idx < total_memories else []
            
            logger.info(f"List memories for user {uid_for_logging} returned {len(paginated_memories)} memories (total: {total_memories}).")
            logger.info("----------------------------------------------------------------------")
            
            return {
                "status": "success",
                "memories": paginated_memories,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_items": total_memories,
                    "total_pages": (total_memories + page_size - 1) // page_size if page_size > 0 else 0
                }
            }
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[MCP ERROR] list_memories: Error listing memories for user '{uid_for_logging}': {e}", exc_info=True)
        logger.info("----------------------------------------------------------------------")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error listing memories: {str(e)}")

@mcp.tool(description="Delete all memories for the current user. This is a destructive operation and should be used with caution.")
async def delete_all_memories(ctx: Context) -> dict[str, Any]:
    user_id_str = None
    client_name_str = None
    uid_for_logging = "unknown_user"

    try:
        logger.info("----------------------------------------------------------------------")
        logger.info(f"[MCP INFO] delete_all_memories: Attempting to access auth_claims from context.")

        # 인증 정보 가져오기
        auth_claims = None
        auth_source = None

        try:
            request = ctx.get_http_request()
            if request and 'auth_claims' in request.scope:
                auth_claims = request.scope['auth_claims']
                auth_source = "request.scope['auth_claims']"
                logger.info(f"[MCP DEBUG] Found auth_claims via request.scope['auth_claims']: {auth_claims}")
        except Exception as e_scope:
            logger.debug(f"[MCP DEBUG] Could not access request.scope['auth_claims']: {e_scope}")

        # 인증 정보 확인
        if auth_claims:
            logger.info(f"[MCP INFO] Successfully retrieved auth_claims via {auth_source}: {auth_claims}")
        else:
            logger.error("[MCP ERROR] Failed to retrieve auth_claims through any method")
            raise HTTPException(status_code=401, detail="Authentication failed: Could not retrieve auth claims")

        if auth_claims:
            user_id_str = auth_claims.get("sub")
            client_name_str = auth_claims.get("client_name", "mcp_inspector_client")
            
            if not user_id_str:
                logger.error(f"[MCP ERROR] delete_all_memories: 'sub' (User ID) not found in auth_claims. Claims: {json.dumps(auth_claims)}")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User ID ('sub') missing from token claims.")
            
            uid_for_logging = f"{client_name_str}:{user_id_str}"
            logger.info(f"[MCP INFO] delete_all_memories: User '{uid_for_logging}' attempting to delete all memories via {auth_source}.")
            logger.info(f"[MCP INFO] delete_all_memories: Full auth_claims: {json.dumps(auth_claims, indent=4)}")
        else:
            logger.warning("[MCP WARNING] delete_all_memories: Failed to retrieve auth_claims from any source. Cannot identify user.")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication claims not found in context.")

        logger.info(f"delete_all_memories processing for user {uid_for_logging}. THIS IS A DESTRUCTIVE OPERATION.")

        # 메모리 클라이언트 가져오기
        memory_client = get_memory_client_safe()
        if not memory_client:
            logger.error(f"[MCP ERROR] delete_all_memories: Memory system is unavailable for user '{uid_for_logging}'")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Memory system is currently unavailable. Please try again later.")
        
        try:
            db = SessionLocal()
            try:
                # 사용자 및 앱 정보 가져오기
                user, app = get_user_and_app(db, user_id=user_id_str, app_id=client_name_str)
                
                # 앱이 활성 상태인지 확인
                if not app.is_active:
                    logger.error(f"[MCP ERROR] delete_all_memories: App {app.name} is paused for user '{uid_for_logging}'")
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                                       detail=f"App {app.name} is currently paused on OpenMemory. Cannot delete memories.")
                
                # 사용자의 메모리 가져오기
                user_memories = db.query(Memory).filter(Memory.user_id == user.id).all()
                accessible_memory_ids = [memory.id for memory in user_memories if check_memory_access_permissions(db, memory, app.id)]
                
                # 접근 가능한 메모리만 삭제
                deleted_count = 0
                for memory_id in accessible_memory_ids:
                    try:
                        memory_client.delete(memory_id)
                    except Exception as delete_error:
                        logger.warning(f"Failed to delete memory {memory_id} from vector store: {delete_error}")
                
                # 각 메모리의 상태 업데이트 및 기록 생성
                now = datetime.datetime.now(datetime.UTC)
                for memory_id in accessible_memory_ids:
                    memory = db.query(Memory).filter(Memory.id == memory_id).first()
                    # 메모리 상태 업데이트
                    memory.state = MemoryState.deleted
                    memory.deleted_at = now
                    deleted_count += 1
                    
                    # 기록 생성
                    history = MemoryStatusHistory(
                        memory_id=memory_id,
                        changed_by=user.id,
                        old_state=MemoryState.active,
                        new_state=MemoryState.deleted
                    )
                    db.add(history)
                    
                    # 접근 로그 생성
                    access_log = MemoryAccessLog(
                        memory_id=memory_id,
                        app_id=app.id,
                        access_type="delete_all",
                        metadata_={"operation": "bulk_delete"}
                    )
                    db.add(access_log)
                
                db.commit()
                logger.info(f"All active memories for user '{uid_for_logging}' (client: {client_name_str}) marked as DELETED. Count: {deleted_count}.")
                return {"status": "success", "message": f"All memories for user {uid_for_logging} have been marked as deleted. Count: {deleted_count}."}
            finally:
                db.close()
        except HTTPException:
            raise
        except Exception as e: # Handles DB-specific errors
            logger.error(f"[MCP ERROR] delete_all_memories: Database error while deleting memories for user '{uid_for_logging}': {e}", exc_info=True)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error during deletion: {str(e)}")

    except HTTPException as http_exc:
        logger.info(f"[MCP INFO] delete_all_memories: HTTPException caught for user '{uid_for_logging}': {http_exc.detail}")
        raise http_exc # Re-raise already formed HTTPException
    except Exception as e: # Catch any other unexpected errors in the main try block
        logger.error(f"[MCP CRITICAL] delete_all_memories: Unexpected critical error for user '{uid_for_logging}': {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected critical error occurred: {str(e)}")
    finally:
        logger.info(f"[MCP INFO] delete_all_memories: Completed for {uid_for_logging if uid_for_logging != 'unknown_user' else 'request'}.")
        logger.info("---------------------------------------------------------------------- END delete_all_memories")


from fastapi import Request
from starlette.responses import Response

async def mcp_streamable_http(request: Request):
    logger.debug("""[MCP_STREAMABLE_HTTP DEBUG] Inspecting incoming request.scope:""")
    try:
        if request.scope:
            logger.debug(f"[MCP_STREAMABLE_HTTP DEBUG] request.scope type: {type(request.scope)}")
            # Ensure request.scope is a dictionary before trying to access keys or get
            if isinstance(request.scope, dict):
                logger.debug(f"[MCP_STREAMABLE_HTTP DEBUG] request.scope keys: {list(request.scope.keys())}")
                if "auth_claims" in request.scope:
                    logger.info(f"[MCP_STREAMABLE_HTTP INFO] 'auth_claims' FOUND in request.scope. Value: {request.scope.get('auth_claims')}")
                else:
                    logger.warning("[MCP_STREAMABLE_HTTP WARNING] 'auth_claims' NOT FOUND in request.scope.")
                # Log other potentially relevant parts of the scope
                logger.debug(f"[MCP_STREAMABLE_HTTP DEBUG] request.scope['type']: {request.scope.get('type')}")
                logger.debug(f"[MCP_STREAMABLE_HTTP DEBUG] request.scope['method']: {request.scope.get('method')}")
                logger.debug(f"[MCP_STREAMABLE_HTTP DEBUG] request.scope['path']: {request.scope.get('path')}")
                logger.debug(f"[MCP_STREAMABLE_HTTP DEBUG] request.scope['headers']: {[(k.decode('latin-1'), v.decode('latin-1')) for k, v in request.scope.get('headers', [])]}")
            else:
                logger.warning(f"[MCP_STREAMABLE_HTTP WARNING] request.scope is not a dict, it is: {type(request.scope)}. Cannot inspect further in the usual way.")
        else:
            logger.debug(f"[MCP_STREAMABLE_HTTP DEBUG] request is None or does not have scope attribute")

        # ASGI 스코프 복사 및 경로 수정
        scope = dict(request.scope)
        scope["path"] = "/mcp/"

        # 인증 정보 처리 및 사용자 객체 생성
        class AccessToken:
            def __init__(self, claims):
                self.claims = claims

        class User:
            def __init__(self, access_token):
                self.access_token = access_token

        # auth_claims 처리
        if "auth_claims" in request.scope:
            auth_claims = request.scope["auth_claims"]
            scope["auth_claims"] = auth_claims
            
            # FastMCP의 Context.auth_claims 메소드가 user.access_token.claims에서 값을 가져오므로
            # scope에 user 객체를 생성하고 access_token과 claims를 설정합니다
            scope["user"] = User(AccessToken(auth_claims))
            
            # 추가로 auth.claims도 설정하여 다양한 방식으로 접근 가능하게 함
            scope["auth"] = {"claims": auth_claims}
            
            logger.debug(f"[MCP_STREAMABLE_HTTP DEBUG] Modified scope keys: {list(scope.keys())}")
            logger.debug(f"[MCP_STREAMABLE_HTTP DEBUG] User object in scope: {scope['user'].__dict__ if 'user' in scope else 'None'}")
        else:
            logger.warning("[MCP_STREAMABLE_HTTP WARNING] auth_claims not found in request.scope")
            
            # 인증 정보가 없는 경우에도 빈 객체 생성 (오류 방지)
            empty_claims = {}
            scope["auth_claims"] = empty_claims
            scope["user"] = User(AccessToken(empty_claims))
            scope["auth"] = {"claims": empty_claims}
            logger.warning("[MCP_STREAMABLE_HTTP WARNING] Created empty auth objects in scope as fallback")

        # The old auth logic and context var setting is removed from here.
        # FastMCP's BearerAuthProvider will handle auth.
        # MCPUserContext dependency will handle context vars for tools.

        try:
            asgi_app = mcp.streamable_http_app()
            send_queue = []
            async def send(message):
                send_queue.append(message)
            
            logger.debug(f"Forwarding request to FastMCP streamable_http_app. Scope path: {scope['path']}, method: {scope.get('method')}")
            # Log headers before calling asgi_app to check for Authorization header
            if 'headers' in scope and isinstance(scope['headers'], list):
                headers_dict = {k.decode('latin-1'): v.decode('latin-1') for k, v in scope['headers']}
                logger.debug(f"[MCP_STREAMABLE_HTTP DEBUG] Scope headers before calling asgi_app: {headers_dict}")
                if 'authorization' in headers_dict:
                    logger.info("[MCP_STREAMABLE_HTTP INFO] Authorization header IS PRESENT in scope['headers'] before calling asgi_app.")
                else:
                    logger.warning("[MCP_STREAMABLE_HTTP WARNING] Authorization header IS MISSING in scope['headers'] before calling asgi_app.")
            else:
                logger.warning("[MCP_STREAMABLE_HTTP WARNING] scope['headers'] not found or not a list before calling asgi_app.")
            await asgi_app(scope, request.receive, send)
            
            status = 200 # Default status
            headers = {} # Default headers
            body = b""    # Default body

            # Process messages from asgi_app to construct the response
            for message in send_queue:
                if message["type"] == "http.response.start":
                    status = message["status"]
                    headers = {k.decode('latin-1'): v.decode('latin-1') for k, v in message["headers"]}
                elif message["type"] == "http.response.body":
                    body += message.get("body", b"")
                    # If more_body is False or not present, it's the end of the body for this message
                    # FastMCP streamable_http_app might send multiple body chunks if streaming internally

            # Ensure content-type is application/json if not set, especially for empty/null bodies
            if not body or body.strip() in (b"", b"null"):
                body = b"{}" # Default to empty JSON object if body is effectively empty
            if "content-type" not in headers:
                 headers["content-type"] = "application/json"

            logger.debug(f"Response from FastMCP streamable_http_app. Status: {status}, Headers: {headers}, Body: {body[:200]}... (truncated if long)")
            return Response(content=body, status_code=status, headers=headers)
        except Exception as e:
            logger.exception(f"Exception in mcp_streamable_http: {e}")
            # Return a generic server error if an unhandled exception occurs
            return Response(content=json.dumps({"error": "Internal Server Error", "detail": str(e)}), 
                            status_code=500, 
                            media_type="application/json")
    except Exception as outer_e:
        logger.exception(f"Outer exception in mcp_streamable_http: {outer_e}")
        return Response(content=json.dumps({"error": "Internal Server Error", "detail": str(outer_e)}), 
                        status_code=500, 
                        media_type="application/json")

async def handle_post_message(request: Request):
    """Handle POST messages for SSE"""
    try:
        body = await request.body()

        # Create a simple receive function that returns the body
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        # Create a simple send function that does nothing
        async def send(message):
            return {}

        # Call handle_post_message with the correct arguments
        await sse.handle_post_message(request.scope, receive, send)

        # Return a success response
        return {"status": "ok"}
    finally:
        pass
        # Clean up context variable
        # client_name_var.reset(client_token)

# setup_mcp_server는 더 이상 필요하지 않으므로 제거합니다.
