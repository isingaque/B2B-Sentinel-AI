from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

class DTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

Severity = Literal["info", "warning", "critical"]
Category = Literal["server", "network", "database", "application"]

class LoginRequest(DTO):
    username: str
    password: str

class RunbookStepCreate(DTO):
    instruction: str = Field(min_length=1, max_length=2000)
    is_risky: bool = False

class RunbookCreateRequest(DTO):
    title: str = Field(min_length=1, max_length=200)
    condition_text: str = Field(min_length=1, max_length=5000)
    category: Category | None = None
    severity: Severity | None = None
    is_active: bool = True
    steps: list[RunbookStepCreate] = Field(min_length=1, max_length=30)

class RunbookUpdateRequest(RunbookCreateRequest):
    version: int = Field(ge=1)

class ChecklistUpdateRequest(DTO):
    status: Literal["done", "skipped"]
    note: str | None = Field(default=None, max_length=2000)

    @field_validator("note")
    @classmethod
    def strip_note(cls, v):
        return v.strip() if isinstance(v, str) else v

class CloseIncidentRequest(DTO):
    resolution_note: str = Field(min_length=5, max_length=2000)
