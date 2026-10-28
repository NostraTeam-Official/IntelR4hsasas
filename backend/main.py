"""IntelR4h API — authorized, user-managed Discord ID records only."""
from __future__ import annotations

import hmac
import os
import re
import time
from datetime import datetime, timezone
from typing import Generator, Optional
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Float, ForeignKey, Integer, String, Text, create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

load_dotenv()

APP_NAME = "IntelR4h"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "local-development-secret-change-this")
JWT_ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 8 * 60 * 60
SEARCH_WINDOW_SECONDS = 72 * 60 * 60
SEARCH_LIMIT = 5
SETUP_CODE = os.getenv("INTELR4H_SETUP_CODE", "")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
FRONTEND_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "FRONTEND_ORIGINS", "http://localhost:8888,http://127.0.0.1:8888"
    ).split(",")
    if origin.strip()
]

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:////data/intelr4h.db" if Path("/data").is_dir() else "sqlite:///./intelr4h.db",
)
# Some hosting providers still expose postgres:// URLs; SQLAlchemy uses postgresql+psycopg.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://") :]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://") :]

if ENVIRONMENT == "production" and JWT_SECRET_KEY == "local-development-secret-change-this":
    raise RuntimeError("Production requires a unique JWT_SECRET_KEY environment variable.")

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
password_hasher = PasswordHasher()
# Per-process sliding-window protection. Multi-instance deployments should add a shared limiter.
RATE_BUCKETS: dict[str, list[float]] = {}
RATE_RULES = {
    "/api/login": (5, 60),
    "/api/register": (5, 600),
    "/api/search": (20, 60),
    "/api/records": (20, 60),
    "/api/admin/role": (30, 60),
}


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(16), default="user", index=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    last_seen: Mapped[Optional[float]] = mapped_column(Float, nullable=True)


class AuthorizedRecord(Base):
    __tablename__ = "authorized_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    discord_id: Mapped[str] = mapped_column(String(25), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(100), default="")
    tags: Mapped[str] = mapped_column(String(300), default="")
    approved_summary: Mapped[str] = mapped_column(Text, default="")
    source_note: Mapped[str] = mapped_column(String(300), default="")
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class SearchEvent(Base):
    __tablename__ = "search_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time, index=True)


class SiteState(Base):
    __tablename__ = "site_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)


Base.metadata.create_all(bind=engine)
with SessionLocal() as _seed_db:
    if _seed_db.get(SiteState, 1) is None:
        _seed_db.add(SiteState(id=1, owner_id=None))
        _seed_db.commit()

app = FastAPI(title=APP_NAME, version="1.0.0", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    content_length = request.headers.get("content-length")
    response = None
    if content_length and content_length.isdigit() and int(content_length) > 1_000_000:
        response = JSONResponse(status_code=413, content={"detail": "İstek boyutu sınırı aşıldı."})
    else:
        rule = RATE_RULES.get(request.url.path) if request.method == "POST" else None
        if rule:
            limit, window = rule
            client_ip = request.client.host if request.client else "unknown"
            key = f"{client_ip}:{request.method}:{request.url.path}"
            now_mono = time.monotonic()
            recent = [stamp for stamp in RATE_BUCKETS.get(key, []) if now_mono - stamp < window]
            if len(recent) >= limit:
                response = JSONResponse(
                    status_code=429,
                    content={"detail": {"message": "Çok fazla istek gönderildi. Biraz bekleyip tekrar dene."}},
                )
            else:
                recent.append(now_mono)
                RATE_BUCKETS[key] = recent
        # Keep the in-memory limiter bounded if many different client addresses appear.
        if len(RATE_BUCKETS) > 10000:
            RATE_BUCKETS.clear()
        if response is None:
            response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    if ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def utc_iso(timestamp: Optional[float]) -> Optional[str]:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class RegisterInput(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=10, max_length=128)
    setup_code: Optional[str] = Field(default=None, max_length=200)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        email = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("Geçerli bir e-posta adresi yaz.")
        return email


class LoginInput(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class SearchInput(BaseModel):
    discord_id: str = Field(min_length=5, max_length=25)

    @field_validator("discord_id")
    @classmethod
    def validate_discord_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not re.fullmatch(r"\d{5,25}", cleaned):
            raise ValueError("Discord ID yalnızca 5–25 rakamdan oluşmalı.")
        return cleaned


class RecordInput(BaseModel):
    discord_id: str = Field(min_length=5, max_length=25)
    username: str = Field(default="", max_length=100)
    tags: str = Field(default="", max_length=300)
    approved_summary: str = Field(default="", max_length=2000)
    source_note: str = Field(default="", max_length=300)

    @field_validator("discord_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not re.fullmatch(r"\d{5,25}", cleaned):
            raise ValueError("Discord ID yalnızca rakamlardan oluşmalı.")
        return cleaned

    @field_validator("username", "tags", "approved_summary", "source_note")
    @classmethod
    def trim_text(cls, value: str) -> str:
        return value.strip()


class RoleInput(BaseModel):
    user_id: int = Field(gt=0)
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        if value not in {"admin", "user"}:
            raise ValueError("Rol admin veya user olmalı.")
        return value


def create_token(user: User) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def current_user(
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Oturum açman gerekiyor.")
    token = authorization[7:].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub", "0"))
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Oturumun geçersiz veya süresi dolmuş.")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Hesap bulunamadı.")
    user.last_seen = time.time()
    db.commit()
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Bu bölüm yalnızca yöneticilere açık.")
    return user


def require_owner(user: User = Depends(current_user)) -> User:
    if user.role != "owner":
        raise HTTPException(status_code=403, detail="Bu işlem yalnızca kurucu hesap tarafından yapılabilir.")
    return user


def serialize_record(record: AuthorizedRecord) -> dict:
    return {
        "id": record.id,
        "discord_id": record.discord_id,
        "username": record.username,
        "tags": record.tags,
        "approved_summary": record.approved_summary,
        "source_note": record.source_note,
        "created_at": utc_iso(record.created_at),
    }


def serialize_user(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "created_at": utc_iso(user.created_at),
        "last_seen": utc_iso(user.last_seen),
        "active": bool(user.last_seen and user.last_seen >= time.time() - 120),
    }


@app.get("/api/health")
def health():
    return {"ok": True, "name": APP_NAME}


@app.post("/api/register")
def register(payload: RegisterInput, db: Session = Depends(get_db)):
    if db.scalar(select(User.id).where(User.email == payload.email)) is not None:
        raise HTTPException(status_code=409, detail="Bu e-posta zaten kayıtlı.")

    site_state = db.scalar(select(SiteState).where(SiteState.id == 1).with_for_update())
    if site_state is None:
        site_state = SiteState(id=1, owner_id=None)
        db.add(site_state)
        db.flush()
    requested_setup = (payload.setup_code or "").strip()
    owner_exists = site_state.owner_id is not None or (db.scalar(select(func.count(User.id)).where(User.role == "owner")) or 0) > 0
    role = "user"
    if requested_setup:
        if not SETUP_CODE or not hmac.compare_digest(requested_setup, SETUP_CODE):
            raise HTTPException(status_code=400, detail="Kurulum kodu doğru değil.")
        if owner_exists:
            raise HTTPException(status_code=409, detail="Kurucu hesap zaten oluşturulmuş.")
        role = "owner"

    user = User(
        email=payload.email,
        password_hash=password_hasher.hash(payload.password),
        role=role,
        created_at=time.time(),
        last_seen=time.time(),
    )
    db.add(user)
    try:
        db.flush()
        if role == "owner":
            site_state.owner_id = user.id
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Bu e-posta zaten kayıtlı.")
    db.refresh(user)
    return {"token": create_token(user), "user": serialize_user(user), "token_type": "bearer"}


@app.post("/api/login")
def login(payload: LoginInput, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None:
        # Keep login failure responses uniform to reduce account enumeration.
        raise HTTPException(status_code=401, detail="E-posta veya parola hatalı.")
    try:
        valid = password_hasher.verify(user.password_hash, payload.password)
    except (VerifyMismatchError, InvalidHashError):
        valid = False
    if not valid:
        raise HTTPException(status_code=401, detail="E-posta veya parola hatalı.")
    user.last_seen = time.time()
    db.commit()
    return {"token": create_token(user), "user": serialize_user(user), "token_type": "bearer"}


@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {"user": serialize_user(user), "search_limit": SEARCH_LIMIT, "window_hours": 72}


@app.get("/api/stats")
def stats(user: User = Depends(current_user), db: Session = Depends(get_db)):
    now = time.time()
    return {
        "active_users": db.scalar(select(func.count(User.id)).where(User.last_seen >= now - 120)) or 0,
        "registered_users": db.scalar(select(func.count(User.id))) or 0,
        "saved_records": db.scalar(select(func.count(AuthorizedRecord.id))) or 0,
        "searches_24h": db.scalar(select(func.count(SearchEvent.id)).where(SearchEvent.created_at >= now - 86400)) or 0,
        "as_of": utc_iso(now),
    }


@app.get("/api/quota")
def quota(user: User = Depends(current_user), db: Session = Depends(get_db)):
    cutoff = time.time() - SEARCH_WINDOW_SECONDS
    used = db.scalar(
        select(func.count(SearchEvent.id)).where(
            SearchEvent.user_id == user.id, SearchEvent.created_at >= cutoff
        )
    ) or 0
    oldest = db.scalar(
        select(func.min(SearchEvent.created_at)).where(
            SearchEvent.user_id == user.id, SearchEvent.created_at >= cutoff
        )
    )
    reset_at = (oldest + SEARCH_WINDOW_SECONDS) if used >= SEARCH_LIMIT and oldest else None
    return {
        "used": int(used),
        "limit": SEARCH_LIMIT,
        "remaining": max(0, SEARCH_LIMIT - int(used)),
        "window_hours": 72,
        "reset_at": utc_iso(reset_at),
    }


@app.post("/api/search")
def search_record(payload: SearchInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    now = time.time()
    cutoff = now - SEARCH_WINDOW_SECONDS
    # Locking the account row prevents parallel PostgreSQL requests from overspending quota.
    db.execute(select(User).where(User.id == user.id).with_for_update()).first()
    recent = db.scalars(
        select(SearchEvent)
        .where(SearchEvent.user_id == user.id, SearchEvent.created_at >= cutoff)
        .order_by(SearchEvent.created_at.asc())
    ).all()
    if len(recent) >= SEARCH_LIMIT:
        reset_at = recent[0].created_at + SEARCH_WINDOW_SECONDS
        raise HTTPException(
            status_code=429,
            detail={
                "message": "72 saatlik sorgu hakkın doldu.",
                "reset_at": utc_iso(reset_at),
                "remaining": 0,
            },
        )

    # Searches are logged even when a matching record is not found, to prevent ID enumeration without cost.
    db.add(SearchEvent(user_id=user.id, created_at=now))
    record = db.scalar(select(AuthorizedRecord).where(AuthorizedRecord.discord_id == payload.discord_id))
    db.commit()

    used_now = len(recent) + 1
    return {
        "found": record is not None,
        "record": serialize_record(record) if record else None,
        "quota": {
            "used": used_now,
            "limit": SEARCH_LIMIT,
            "remaining": max(0, SEARCH_LIMIT - used_now),
            "window_hours": 72,
            "reset_at": utc_iso((recent[0].created_at + SEARCH_WINDOW_SECONDS) if len(recent) >= SEARCH_LIMIT - 1 else None),
        },
        "scope": "Yalnızca bu sisteme yetkili olarak eklenen kayıtlar tarandı.",
    }


@app.post("/api/records")
def add_record(payload: RecordInput, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    record = AuthorizedRecord(
        discord_id=payload.discord_id,
        username=payload.username,
        tags=payload.tags,
        approved_summary=payload.approved_summary,
        source_note=payload.source_note,
        created_by_id=user.id,
        created_at=time.time(),
    )
    db.add(record)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Bu Discord ID için kayıt zaten var.")
    db.refresh(record)
    return {"record": serialize_record(record)}


@app.get("/api/records")
def list_records(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    records = db.scalars(
        select(AuthorizedRecord).order_by(AuthorizedRecord.created_at.desc()).limit(100)
    ).all()
    return {"records": [serialize_record(record) for record in records]}


@app.get("/api/users")
def list_users(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.created_at.desc()).limit(200)).all()
    return {"users": [serialize_user(item) for item in users]}


@app.post("/api/admin/role")
def set_role(payload: RoleInput, owner: User = Depends(require_owner), db: Session = Depends(get_db)):
    target = db.get(User, payload.user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")
    if target.role == "owner":
        raise HTTPException(status_code=400, detail="Kurucu hesabın rolü değiştirilemez.")
    if target.id == owner.id:
        raise HTTPException(status_code=400, detail="Kendi kurucu yetkini bu ekrandan değiştiremezsin.")
    target.role = payload.role
    db.commit()
    db.refresh(target)
    return {"user": serialize_user(target)}


# Render deployment: serve the frontend and API from one origin.
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
