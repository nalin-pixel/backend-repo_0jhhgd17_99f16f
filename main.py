import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Path, Query, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from bson import ObjectId
import requests

from database import db, create_document, get_documents
from schemas import Ticket, TicketReply

app = FastAPI(title="Ticket Desk API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- Utilities ----------------

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def serialize_ticket(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = {**doc}
    out["id"] = str(out.pop("_id"))
    # Convert datetime to ISO strings in messages
    msgs = out.get("messages", [])
    for m in msgs:
        if isinstance(m.get("created_at"), datetime):
            m["created_at"] = m["created_at"].astimezone(timezone.utc).isoformat()
    # Top-level timestamps
    for k in ("created_at", "updated_at"):
        if isinstance(out.get(k), datetime):
            out[k] = out[k].astimezone(timezone.utc).isoformat()
    return out


# ---------------- Auth & Tenant Isolation ----------------
class CompanyCtx(BaseModel):
    id: str
    name: Optional[str] = None
    api_key: str


def get_company(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> CompanyCtx:
    if not x_api_key:
        raise HTTPException(401, "Missing X-API-Key")
    doc = db["company"].find_one({"api_key": x_api_key})
    if not doc:
        raise HTTPException(401, "Invalid API key")
    return CompanyCtx(id=str(doc["_id"]), name=doc.get("name"), api_key=x_api_key)


# ---------------- Root / Health ----------------
@app.get("/")
def health():
    return {"ok": True}


@app.get("/test")
def test_database():
    resp = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "collections": [],
    }
    try:
        if db is None:
            resp["database"] = "❌ Not Connected"
        else:
            resp["database"] = "✅ Connected"
            resp["collections"] = db.list_collection_names()
    except Exception as e:
        resp["database"] = f"⚠️ {str(e)[:80]}"
    return resp


# ---------------- Email (Outbound via SendGrid if configured) ----------------
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@ticketdesk.local")


def send_email(to_email: str, subject: str, body: str) -> bool:
    if not SENDGRID_API_KEY:
        print(f"[Email:stub] Would send to {to_email} | {subject}\n{body[:200]}")
        return False
    try:
        resp = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={
                "Authorization": f"Bearer {SENDGRID_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "personalizations": [{"to": [{"email": to_email}]}],
                "from": {"email": FROM_EMAIL},
                "subject": subject,
                "content": [{"type": "text/plain", "value": body}],
            },
            timeout=10,
        )
        ok = 200 <= resp.status_code < 300
        if not ok:
            print("[Email] SendGrid error:", resp.status_code, resp.text[:200])
        return ok
    except Exception as e:
        print("[Email] Exception:", str(e))
        return False


# ---------------- Ticket Endpoints ----------------
@app.post("/api/tickets")
def create_ticket(ticket: Ticket, company: CompanyCtx = Depends(get_company)):
    # Build initial message
    initial = {
        "author_name": ticket.submitter_name,
        "author_email": ticket.submitter_email,
        "body": ticket.message,
        "via": "form",
        "created_at": datetime.now(timezone.utc),
    }
    doc = ticket.model_dump()
    doc["company_id"] = company.id  # enforce tenant
    doc.pop("message", None)  # store message only inside messages[]
    doc.setdefault("messages", []).append(initial)
    inserted_id = create_document("ticket", doc)
    return {"id": inserted_id}


@app.get("/api/tickets")
def list_tickets(
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    company: CompanyCtx = Depends(get_company),
):
    filt: Dict[str, Any] = {"company_id": company.id}
    if status:
        filt["status"] = status
    items = get_documents("ticket", filt, limit)
    items = [serialize_ticket(d) for d in items]
    # Sort newest first by updated_at or created_at
    def _ts(x):
        return x.get("updated_at") or x.get("created_at") or ""
    items.sort(key=_ts, reverse=True)
    return {"items": items}


@app.get("/api/tickets/{ticket_id}")
def get_ticket(ticket_id: str = Path(...), company: CompanyCtx = Depends(get_company)):
    doc = db["ticket"].find_one({"_id": oid(ticket_id), "company_id": company.id})
    if not doc:
        raise HTTPException(404, "Ticket not found")
    return serialize_ticket(doc)


@app.post("/api/tickets/{ticket_id}/reply")
def reply_ticket(ticket_id: str, reply: TicketReply, company: CompanyCtx = Depends(get_company)):
    doc = db["ticket"].find_one({"_id": oid(ticket_id), "company_id": company.id})
    if not doc:
        raise HTTPException(404, "Ticket not found")
    message = {
        "author_name": reply.author_name,
        "author_email": reply.author_email,
        "body": reply.body,
        "via": "email" if reply.send_email else "internal",
        "created_at": datetime.now(timezone.utc),
    }
    db["ticket"].update_one({"_id": oid(ticket_id)}, {
        "$push": {"messages": message},
        "$set": {"updated_at": datetime.now(timezone.utc)}
    })

    if reply.send_email:
        subject = f"Re: {doc.get('subject', 'Your support request')}"
        send_email(doc["submitter_email"], subject, reply.body)

    return {"ok": True}


class StatusPatch(BaseModel):
    status: str


@app.patch("/api/tickets/{ticket_id}/status")
def update_status(ticket_id: str, patch: StatusPatch, company: CompanyCtx = Depends(get_company)):
    if patch.status not in {"open", "pending", "closed"}:
        raise HTTPException(400, "Invalid status")
    res = db["ticket"].update_one({"_id": oid(ticket_id), "company_id": company.id}, {
        "$set": {"status": patch.status, "updated_at": datetime.now(timezone.utc)}
    })
    if res.matched_count == 0:
        raise HTTPException(404, "Ticket not found")
    return {"ok": True}


class AssignPatch(BaseModel):
    assignee: Optional[str]


@app.patch("/api/tickets/{ticket_id}/assign")
def update_assignee(ticket_id: str, patch: AssignPatch, company: CompanyCtx = Depends(get_company)):
    res = db["ticket"].update_one({"_id": oid(ticket_id), "company_id": company.id}, {
        "$set": {"assignee": patch.assignee, "updated_at": datetime.now(timezone.utc)}
    })
    if res.matched_count == 0:
        raise HTTPException(404, "Ticket not found")
    return {"ok": True}


class PriorityPatch(BaseModel):
    priority: str


@app.patch("/api/tickets/{ticket_id}/priority")
def update_priority(ticket_id: str, patch: PriorityPatch, company: CompanyCtx = Depends(get_company)):
    if patch.priority not in {"low", "medium", "high"}:
        raise HTTPException(400, "Invalid priority")
    res = db["ticket"].update_one({"_id": oid(ticket_id), "company_id": company.id}, {
        "$set": {"priority": patch.priority, "updated_at": datetime.now(timezone.utc)}
    })
    if res.matched_count == 0:
        raise HTTPException(404, "Ticket not found")
    return {"ok": True}


# ---------------- Email Inbound Webhook ----------------
class InboundEmail(BaseModel):
    company_api_key: Optional[str] = None
    company_id: Optional[str] = None
    from_name: Optional[str] = None
    from_email: str
    subject: Optional[str] = None
    body: str
    thread_ticket_id: Optional[str] = None


@app.post("/api/email/inbound")
def inbound_email(payload: InboundEmail):
    # Resolve company by api key if provided; else by company_id
    comp = None
    if payload.company_api_key:
        comp = db["company"].find_one({"api_key": payload.company_api_key})
    elif payload.company_id:
        try:
            comp = db["company"].find_one({"_id": oid(payload.company_id)})
        except HTTPException:
            comp = None
    if not comp:
        raise HTTPException(401, "Unknown company for inbound email")
    comp_id = str(comp["_id"])

    if payload.thread_ticket_id:
        doc = db["ticket"].find_one({"_id": oid(payload.thread_ticket_id), "company_id": comp_id})
        if not doc:
            raise HTTPException(404, "Ticket not found for threading")
        msg = {
            "author_name": payload.from_name or payload.from_email,
            "author_email": payload.from_email,
            "body": payload.body,
            "via": "email",
            "created_at": datetime.now(timezone.utc),
        }
        db["ticket"].update_one({"_id": oid(payload.thread_ticket_id)}, {
            "$push": {"messages": msg},
            "$set": {"updated_at": datetime.now(timezone.utc)}
        })
        return {"ok": True, "action": "appended"}

    # Create a new ticket from email
    ticket = Ticket(
        company_id=comp_id,
        submitter_name=payload.from_name or payload.from_email,
        submitter_email=payload.from_email,
        subject=payload.subject or "(no subject)",
        message=payload.body,
    )
    created = create_ticket(ticket, CompanyCtx(id=comp_id, api_key=comp.get("api_key")))
    return {"ok": True, "action": "created", "id": created.get("id")}


# ---------------- Company Management ----------------
class Company(BaseModel):
    name: str
    domain: Optional[str] = None
    api_key: str


@app.post("/api/companies")
def create_company(company: Company):
    if db["company"].find_one({"api_key": company.api_key}):
        raise HTTPException(400, "api_key already exists")
    cid = create_document("company", company.model_dump())
    return {"id": cid}


@app.get("/api/companies")
def list_companies(limit: int = 50):
    items = get_documents("company", {}, limit)
    out = []
    for c in items:
        c["id"] = str(c.pop("_id"))
        out.append(c)
    return {"items": out}
