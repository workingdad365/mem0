# app/auth_middleware.py

DEFAULT_AUDIENCE = "openmemory-mcp-server"
import logging

# Explicit logger setup for this module
logger = logging.getLogger(__name__) # __name__ will be 'app.auth_middleware'
logger.setLevel(logging.DEBUG) # Set to DEBUG to see all messages from this logger

# Add a handler if not already configured by uvicorn or main app's logging setup
if not logger.handlers:
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

import time
from typing import Optional, Dict, Any, List

import time
from jose import jwt, jwk, JWTError, exceptions as jose_exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from fastapi import status
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, issuer_url: str, audience: Optional[str] = None, public_key_path: Optional[str] = None, excluded_paths: Optional[List[str]] = None):
        super().__init__(app)
        self.issuer_url = issuer_url
        self.audience = audience
        self.public_key_path = public_key_path
        self.excluded_paths = excluded_paths or []
        self._public_key_jwk: Optional[Dict[str, Any]] = None
        self._load_public_key()
        logger.info(f"AuthMiddleware initialized. Issuer: {self.issuer_url}, Audience: {self.audience}, PublicKeyPath: {self.public_key_path}, Excluded Paths: {self.excluded_paths}")
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        logger.info(f"AuthMiddleware ENTER dispatch for path: {request.url.path}")

        for excluded_path in self.excluded_paths:
            if request.url.path.startswith(excluded_path):
                logger.debug(f"AuthMiddleware: Path {request.url.path} is excluded, skipping auth processing.")
                response = await call_next(request)
                logger.info(f"AuthMiddleware EXIT dispatch for excluded path: {request.url.path}")
                return response

        auth_header = request.headers.get("Authorization")
        token = None
        token: Optional[str] = None

        if auth_header:
            logger.debug(f"AuthMiddleware: Authorization header found: {auth_header[:30]}...") # Log prefix
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                token = parts[1]
                logger.debug(f"AuthMiddleware: Token extracted: {token[:20]}...") # Log prefix
            else:
                logger.warning(f"AuthMiddleware: Malformed Authorization header: {auth_header[:30]}...")
        else:
            logger.debug(f"AuthMiddleware: No Authorization header found for path {request.url.path}")

        if token:
            try:
                if not self._public_key_jwk:
                    logger.error(f"JWT validation error for path {request.url.path}: Public key not loaded.")
                    return await self._unauthorized_response(request, "Public key not loaded.")

                algorithms = self._public_key_jwk.get("alg") or "RS256"
                if isinstance(algorithms, str):
                    algorithms = [algorithms]

                payload = jwt.decode(
                    token,
                    self._public_key_jwk, # Pass the loaded JWK directly
                    algorithms=algorithms, # Specify algorithms based on the key type
                    issuer=self.issuer_url,
                    audience=self.audience
                )
                request.scope["auth_claims"] = payload
                logger.info(f"AuthMiddleware: Successfully set auth_claims for user {payload.get('sub')} on path {request.url.path}")
                logger.info(f"Successfully validated token and set auth_claims for user '{payload.get('sub', 'unknown')}' on path {request.url.path}")

            except jose_exceptions.ExpiredSignatureError as e:
                logger.warning(f"JWT validation error for path {request.url.path}: Expired token - {e}", exc_info=True)
                return await self._unauthorized_response(request, f"Token has expired: {e}")
            except jose_exceptions.JWTClaimsError as e:
                logger.warning(f"JWT validation error for path {request.url.path}: Invalid claims - {e}", exc_info=True)
                return await self._unauthorized_response(request, f"Invalid claims: {e}")
            except JWTError as e:
                logger.warning(f"JWT validation error for path {request.url.path}: General JWT error (e.g., signature mismatch, malformed) - {e}", exc_info=True)
                return await self._unauthorized_response(request, f"Invalid token: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during token processing for path {request.url.path}: {e}", exc_info=True)
                return await self._unauthorized_response(request, f"An unexpected error occurred: {e}")
        else:
            logger.debug(f"No token to process for path {request.url.path}, auth_claims not set.")

        response = await call_next(request)
        logger.info(f"AuthMiddleware EXIT dispatch for path: {request.url.path}")
        return response

    def _load_public_key(self):
        if not self.public_key_path:
            logger.error("Public key path not provided to AuthMiddleware.")
            self._public_key_jwk = None
            return

        try:
            with open(self.public_key_path, "rb") as key_file:
                public_key_pem = key_file.read()
            
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            self._public_key_jwk = jwk.construct(public_key, algorithm='RS256').to_dict()
            if 'alg' not in self._public_key_jwk:
                self._public_key_jwk['alg'] = 'RS256' # Default for RSA
            if 'kid' not in self._public_key_jwk: # Add a default kid if not present
                self._public_key_jwk['kid'] = 'local_dev_key'

            logger.info(f"Successfully loaded public key from {self.public_key_path} and constructed JWK.")
            #logger.debug(f"Constructed JWK: {self._public_key_jwk}")

        except FileNotFoundError:
            logger.error(f"Public key file not found at {self.public_key_path}")
            self._public_key_jwk = None
        except ValueError as e: 
            logger.error(f"Error loading PEM public key from {self.public_key_path}: {e}", exc_info=True)
            self._public_key_jwk = None
        except Exception as e:
            logger.error(f"Unexpected error loading public key from {self.public_key_path}: {e}", exc_info=True)
            self._public_key_jwk = None

    async def _unauthorized_response(self, request: Request, detail: str) -> Response:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": detail},
            headers={"WWW-Authenticate": "Bearer"},
        )
