from pydantic import BaseModel


class ToolHealth(BaseModel):
    name: str
    available: bool
    command: list[str]
    version: str | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    status: str
    app_name: str
    app_version: str
    database: bool
    tools: list[ToolHealth]
