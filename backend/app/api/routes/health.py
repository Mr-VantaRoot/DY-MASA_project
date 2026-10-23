from fastapi import APIRouter

from app.core.config import get_settings
from app.db.session import check_database
from app.schemas.health import HealthResponse, ToolHealth
from app.services.tool_checker import ToolChecker


router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    database_ok = False
    try:
        database_ok = check_database()
    except Exception:
        database_ok = False

    # Health must execute the configured tools, not only check whether their files exist.
    tools = [ToolHealth(**tool.__dict__) for tool in ToolChecker(settings).check_all()]
    all_ok = database_ok and all(tool.available for tool in tools)

    return HealthResponse(
        status="ok" if all_ok else "degraded",
        app_name=settings.app_name,
        app_version=settings.app_version,
        database=database_ok,
        tools=tools,
    )
