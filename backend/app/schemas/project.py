from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=2000)
    repository_url: HttpUrl | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class ProjectRead(BaseModel):
    id: str
    name: str
    description: str
    repository_url: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
