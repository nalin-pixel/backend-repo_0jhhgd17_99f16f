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
    company_id: str = Field(..., description="Tenant/company identifier")
    submitter_name: str
    submitter_email: EmailStr
    subject: str
    message: str = Field(..., description="Initial message body from form")
    status: str = Field("open", description="open | pending | closed")
    priority: str = Field("medium", description="low | medium | high")
    assignee: Optional[str] = None
    messages: List[TicketMessage] = Field(default_factory=list)

class TicketReply(BaseModel):
    author_name: str
    author_email: EmailStr
    body: str
    send_email: bool = True

# Simple auth schema if needed in the future
class AuthContext(BaseModel):
    company_id: str
    api_key: Optional[str] = None
