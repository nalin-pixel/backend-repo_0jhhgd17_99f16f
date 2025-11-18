import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Path, Query, Header, Depends, Response, Cookie
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId
import requests
import bcrypt

from database import db, create_document, get_documents
from schemas import Ticket, TicketReply, UserCreate, UserLogin, UserOut

app = FastAPI(title="Ticket Desk API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
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


# ---------------- Session Auth ----------------
SESSION_COOKIE = "session"
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "43200"))  # 30 days


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except Exception:
        return False


class SessionUser(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    company_id: str


def get_session_user(
    session: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> Optional[SessionUser]:
    sid = None
    if session:
        sid = session
    # Support Authorization: Bearer <sid>
    if authorization and authorization.lower().startswith("bearer "):
        sid = authorization.split(" ", 1)[1].strip()
    if not sid:
        return None
    sdoc = db["session"].find_one({"_id": sid})
    if not sdoc:
        return None
    # Expiry check
    if sdoc.get("expires_at") and sdoc["expires_at"] < datetime.now(timezone.utc):
        db["session"].delete_one({"_id": sid})
        return None
    return SessionUser(**sdoc["user"])


def require_user(user: Optional[SessionUser] = Depends(get_session_user)) -> SessionUser:
    if not user:
        raise HTTPException(401, "Not authenticated")
    return user


def require_admin(user: SessionUser = Depends(require_user)) -> SessionUser:
    if user.role != "admin":
        raise HTTPException(403, "Admin only")
    return user


# ---------------- SaaS Signup ----------------
class SignupPayload(BaseModel):
    company_name: str
    name: str
    email: EmailStr
    password: str


@app.post("/api/auth/signup")
def signup(payload: SignupPayload):
    # Enforce unique email globally for simplicity
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(400, "Email already in use")
    # Create company
    company_doc = {
        "name": payload.company_name,
        "created_at": datetime.now(timezone.utc),
    }
    company_id = create_document("company", company_doc)
    # Create admin user
    user_doc = {
        "company_id": company_id,
        "name": payload.name,
        "email": payload.email,
        "role": "admin",
        "password_hash": hash_password(payload.password),
        "created_at": datetime.now(timezone.utc),
    }
    user_id = create_document("user", user_doc)
    return {"ok": True, "company_id": company_id, "user_id": user_id}


# ---------------- Users ----------------
@app.post("/api/auth/register")
def register_user(payload: UserCreate, admin: SessionUser = Depends(require_admin)):
    if payload.role not in {"agent", "admin"}:
        raise HTTPException(400, "Invalid role")
    # Enforce unique email globally for simplicity
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(400, "Email already registered")
    doc = {
        "company_id": admin.company_id,
        "name": payload.name,
        "email": payload.email,
        "role": payload.role,
        "password_hash": hash_password(payload.password),
        "created_at": datetime.now(timezone.utc),
    }
    uid = create_document("user", doc)
    return {"id": uid}


@app.post("/api/auth/login")
def login_user(payload: UserLogin, response: Response):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", b"")):
        raise HTTPException(401, "Invalid credentials")
    # Create session
    sid = os.urandom(24).hex()
    expires = datetime.now(timezone.utc) + timedelta(minutes=SESSION_TTL_MINUTES)
    sess = {
        "_id": sid,
        "user": {
            "id": str(user["_id"]),
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "company_id": user["company_id"],
        },
        "company_id": user["company_id"],
        "created_at": datetime.now(timezone.utc),
        "expires_at": expires,
    }
    db["session"].insert_one(sess)
    # HttpOnly cookie
    response.set_cookie(
        key=SESSION_COOKIE,
        value=sid,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=SESSION_TTL_MINUTES * 60,
        path="/",
    )
    return {"ok": True, "session": sid}


@app.post("/api/auth/logout")
def logout_user(
    response: Response,
    session: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
):
    sid = None
    if session:
        sid = session
    if authorization and authorization.lower().startswith("bearer "):
        sid = authorization.split(" ", 1)[1].strip()
    if sid:
        db["session"].delete_one({"_id": sid})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def get_me(user: SessionUser = Depends(require_user)):
    return user


class RolePatch(BaseModel):
    role: str


@app.get("/api/users")
def list_users(user: SessionUser = Depends(require_admin)):
    items = list(db["user"].find({"company_id": user.company_id}).limit(200))
    out: List[UserOut] = []  # type: ignore
    for u in items:
        out.append(UserOut(id=str(u["_id"]), name=u["name"], email=u["email"], role=u["role"]))
    return {"items": [o.model_dump() for o in out]}


@app.patch("/api/users/{user_id}/role")
def change_role(user_id: str, patch: RolePatch, user: SessionUser = Depends(require_admin)):
    if patch.role not in {"agent", "admin"}:
        raise HTTPException(400, "Invalid role")
    res = db["user"].update_one({"_id": oid(user_id), "company_id": user.company_id}, {"$set": {"role": patch.role}})
    if res.matched_count == 0:
        raise HTTPException(404, "User not found")
    return {"ok": True}


@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, user: SessionUser = Depends(require_admin)):
    res = db["user"].delete_one({"_id": oid(user_id), "company_id": user.company_id})
    return {"deleted": res.deleted_count}


# ---------------- Ticket Endpoints ----------------
@app.post("/api/tickets")
def create_ticket(ticket: Ticket, user: SessionUser = Depends(require_user)):
    # Build initial message
    initial = {
        "author_name": ticket.submitter_name,
        "author_email": ticket.submitter_email,
        "body": ticket.message,
        "via": "form",
        "created_at": datetime.now(timezone.utc),
    }
    doc = ticket.model_dump()
    # enforce tenant from session
    doc["company_id"] = user.company_id
    doc.pop("message", None)  # store message only inside messages[]
    doc.setdefault("messages", []).append(initial)
    inserted_id = create_document("ticket", doc)
    return {"id": inserted_id}


@app.get("/api/tickets")
def list_tickets(
    status: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="full-text search"),
    limit: int = Query(50, ge=1, le=200),
    user: SessionUser = Depends(require_user),
):
    filt: Dict[str, Any] = {"company_id": user.company_id}
    if status:
        filt["status"] = status
    # Search by subject, submitter, messages.body, tags
    if q:
        filt["$or"] = [
            {"subject": {"$regex": q, "$options": "i"}},
            {"submitter_name": {"$regex": q, "$options": "i"}},
            {"submitter_email": {"$regex": q, "$options": "i"}},
            {"messages.body": {"$regex": q, "$options": "i"}},
            {"tags": {"$elemMatch": {"$regex": q, "$options": "i"}}},
        ]
    items = get_documents("ticket", filt, limit)
    items = [serialize_ticket(d) for d in items]
    # Sort newest first by updated_at or created_at
    def _ts(x):
        return x.get("updated_at") or x.get("created_at") or ""
    items.sort(key=_ts, reverse=True)
    return {"items": items}


@app.get("/api/tickets/{ticket_id}")
def get_ticket(ticket_id: str = Path(...), user: SessionUser = Depends(require_user)):
    doc = db["ticket"].find_one({"_id": oid(ticket_id), "company_id": user.company_id})
    if not doc:
        raise HTTPException(404, "Ticket not found")
    return serialize_ticket(doc)


@app.post("/api/tickets/{ticket_id}/reply")
def reply_ticket(ticket_id: str, reply: TicketReply, user: SessionUser = Depends(require_user)):
    doc = db["ticket"].find_one({"_id": oid(ticket_id), "company_id": user.company_id})
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
def update_status(ticket_id: str, patch: StatusPatch, user: SessionUser = Depends(require_user)):
    if patch.status not in {"open", "pending", "closed"}:
        raise HTTPException(400, "Invalid status")
    res = db["ticket"].update_one({"_id": oid(ticket_id), "company_id": user.company_id}, {
        "$set": {"status": patch.status, "updated_at": datetime.now(timezone.utc)}
    })
    if res.matched_count == 0:
        raise HTTPException(404, "Ticket not found")
    return {"ok": True}


class AssignPatch(BaseModel):
    assignee: Optional[str]


@app.patch("/api/tickets/{ticket_id}/assign")
def update_assignee(ticket_id: str, patch: AssignPatch, user: SessionUser = Depends(require_user)):
    res = db["ticket"].update_one({"_id": oid(ticket_id), "company_id": user.company_id}, {
        "$set": {"assignee": patch.assignee, "updated_at": datetime.now(timezone.utc)}
    })
    if res.matched_count == 0:
        raise HTTPException(404, "Ticket not found")
    return {"ok": True}


class PriorityPatch(BaseModel):
    priority: str


@app.patch("/api/tickets/{ticket_id}/priority")
def update_priority(ticket_id: str, patch: PriorityPatch, user: SessionUser = Depends(require_user)):
    if patch.priority not in {"low", "medium", "high"}:
        raise HTTPException(400, "Invalid priority")
    res = db["ticket"].update_one({"_id": oid(ticket_id), "company_id": user.company_id}, {
        "$set": {"priority": patch.priority, "updated_at": datetime.now(timezone.utc)}
    })
    if res.matched_count == 0:
        raise HTTPException(404, "Ticket not found")
    return {"ok": True}


class TagsPatch(BaseModel):
    tags: List[str]


@app.patch("/api/tickets/{ticket_id}/tags")
def update_tags(ticket_id: str, patch: TagsPatch, user: SessionUser = Depends(require_user)):
    res = db["ticket"].update_one({"_id": oid(ticket_id), "company_id": user.company_id}, {
        "$set": {"tags": patch.tags, "updated_at": datetime.now(timezone.utc)}
    })
    if res.matched_count == 0:
        raise HTTPException(404, "Ticket not found")
    return {"ok": True}


class BulkAction(BaseModel):
    ids: List[str]
    action: str
    value: Optional[str] = None


@app.post("/api/tickets/bulk")
def bulk_update(payload: BulkAction, user: SessionUser = Depends(require_user)):
    if not payload.ids:
        raise HTTPException(400, "No ids provided")
    obj_ids = []
    for i in payload.ids:
        try:
            obj_ids.append(oid(i))
        except HTTPException:
            continue
    if not obj_ids:
        return {"updated": 0}

    update = {"$set": {"updated_at": datetime.now(timezone.utc)}}
    if payload.action == "status" and payload.value in {"open", "pending", "closed"}:
        update["$set"]["status"] = payload.value
    elif payload.action == "priority" and payload.value in {"low", "medium", "high"}:
        update["$set"]["priority"] = payload.value
    elif payload.action == "assign":
        update["$set"]["assignee"] = payload.value
    else:
        raise HTTPException(400, "Invalid action or value")

    res = db["ticket"].update_many({"_id": {"$in": obj_ids}, "company_id": user.company_id}, update)
    return {"updated": res.modified_count}


# ---------------- Email Inbound Webhook ----------------
class InboundEmail(BaseModel):
    company_id: Optional[str] = None
    from_name: Optional[str] = None
    from_email: str
    subject: Optional[str] = None
    body: str
    thread_ticket_id: Optional[str] = None


@app.post("/api/email/inbound")
def inbound_email(payload: InboundEmail):
    # Resolve company by id
    comp = None
    if payload.company_id:
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
    # Create ticket directly; assign company by comp_id
    # Reuse logic similar to create_ticket without auth
    initial = {
        "author_name": ticket.submitter_name,
        "author_email": ticket.submitter_email,
        "body": ticket.message,
        "via": "email",
        "created_at": datetime.now(timezone.utc),
    }
    doc = ticket.model_dump()
    doc.pop("message", None)
    doc.setdefault("messages", []).append(initial)
    inserted_id = create_document("ticket", doc)
    return {"ok": True, "action": "created", "id": inserted_id}


# ---------------- Companies (read-only helpers) ----------------
class Company(BaseModel):
    name: str
    domain: Optional[str] = None


@app.get("/api/companies")
def list_companies(limit: int = 50):
    items = get_documents("company", {}, limit)
    out = []
    for c in items:
        c["id"] = str(c.pop("_id"))
        out.append(c)
    return {"items": out}
