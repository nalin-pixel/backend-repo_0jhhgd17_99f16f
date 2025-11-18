from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

# Ticket message structure used inside Ticket.messages
class TicketMessage(BaseModel):
    author_name: str
    author_email: EmailStr
    body: str
    via: str = Field("form", description="form | email | internal")
    created_at: Optional[str] = Field(default=None, description="ISO timestamp")

class Ticket(BaseModel):
    # Make company_id optional for create flows; backend will set it from session
    company_id: Optional[str] = Field(default=None, description="Tenant/company identifier")
    submitter_name: str
    submitter_email: EmailStr
    subject: str
    message: str = Field(..., description="Initial message body from form")
    status: str = Field("open", description="open | pending | closed")
    priority: str = Field("medium", description="low | medium | high")
    assignee: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    messages: List[TicketMessage] = Field(default_factory=list)

class TicketReply(BaseModel):
    author_name: str
    author_email: EmailStr
    body: str
    send_email: bool = True

# Auth & Users
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = Field("agent", description="agent | admin")

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str

# Simple auth schema if needed in the future
class AuthContext(BaseModel):
    company_id: str
    api_key: Optional[str] = None
