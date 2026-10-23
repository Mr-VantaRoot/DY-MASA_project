from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.health import router as health_router
from app.api.routes.jobs import router as jobs_router
from app.api.routes.terminal import router as terminal_router
from app.api.routes.dynamic import router as dynamic_router
from app.core.config import get_settings
from app.db.session import init_db
from app.services.job_service import cleanup_interrupted_jobs, dispatch_queued_jobs


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router, prefix="/api")
    app.include_router(jobs_router, prefix="/api")
    if settings.enable_terminal:
        app.include_router(terminal_router, prefix="/api")
    app.include_router(dynamic_router, prefix="/api")

    @app.on_event("startup")
    def on_startup() -> None:
        for directory in (settings.upload_dir, settings.workspace_dir, settings.report_dir):
            directory.mkdir(parents=True, exist_ok=True)
        init_db()
        cleanup_interrupted_jobs(settings)
        dispatch_queued_jobs(settings)

    return app


app = create_app()
