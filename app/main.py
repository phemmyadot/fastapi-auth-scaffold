from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.exceptions import AuthError, NotFoundError, PermissionError, ValidationError
from app.core.rate_limit import limiter


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.PROJECT_NAME,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Rate limiting
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # CORS
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security headers middleware (Spec §8)
    application.add_middleware(SecurityHeadersMiddleware)

    # Exception handlers (RFC 7807 Problem JSON)
    application.add_exception_handler(AuthError, _auth_error_handler)
    application.add_exception_handler(NotFoundError, _not_found_handler)
    application.add_exception_handler(PermissionError, _permission_error_handler)
    application.add_exception_handler(ValidationError, _validation_error_handler)
    application.add_exception_handler(Exception, _internal_error_handler)

    # Routes
    application.include_router(api_router)

    return application


# --- Security Headers Middleware (Spec §8) ---

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


# --- RFC 7807 Problem JSON Error Handlers ---

def _problem_json(status: int, title: str, detail: str, instance: str = "") -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "type": f"about:blank",
            "title": title,
            "status": status,
            "detail": detail,
            "instance": instance,
        },
    )


async def _auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    return _problem_json(exc.status_code, "Authentication Error", exc.detail, str(request.url))


async def _not_found_handler(request: Request, exc: NotFoundError) -> JSONResponse:
    return _problem_json(exc.status_code, "Not Found", exc.detail, str(request.url))


async def _permission_error_handler(request: Request, exc: PermissionError) -> JSONResponse:
    return _problem_json(exc.status_code, "Forbidden", exc.detail, str(request.url))


async def _validation_error_handler(request: Request, exc: ValidationError) -> JSONResponse:
    return _problem_json(exc.status_code, "Validation Error", exc.detail, str(request.url))


async def _internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Never expose internal stack traces (Spec §8)
    return _problem_json(500, "Internal Server Error", "An unexpected error occurred.", str(request.url))


app = create_app()
