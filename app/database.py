import os
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from dotenv import load_dotenv
from sqlalchemy import JSON, DateTime, Float, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL:
    (ROOT / "data").mkdir(exist_ok=True)
    DATABASE_URL = "sqlite:///" + str(ROOT / "data" / "postmark.db")
elif DATABASE_URL.startswith(("postgres://", "postgresql://")):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL.split("://", 1)[1]

engine = create_engine(DATABASE_URL, pool_pre_ping=True,
                       connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {"connect_timeout": 10})
SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    sender: Mapped[str] = mapped_column(String(320))
    subject: Mapped[str] = mapped_column(String(998))
    body: Mapped[str] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[int] = mapped_column(Integer)
    summary: Mapped[str] = mapped_column(Text)
    signals: Mapped[list] = mapped_column(JSON)
    categories: Mapped[dict] = mapped_column(JSON)
    word_count: Mapped[int] = mapped_column(Integer)
    link_count: Mapped[int] = mapped_column(Integer)
    elapsed_ms: Mapped[float] = mapped_column(Float)
    engine_version: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session


def initialize_database(bind=engine):
    """Add ownership without assigning pre-authentication history to any account."""
    with bind.begin() as connection:
        inspector = inspect(connection)
        if inspector.has_table("analyses"):
            if "user_id" not in {column["name"] for column in inspector.get_columns("analyses")}:
                connection.execute(text("ALTER TABLE analyses ADD COLUMN user_id VARCHAR(255)"))
        Base.metadata.create_all(connection)
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_analyses_user_id ON analyses (user_id)"))


def serialize(row: Analysis) -> dict:
    result = {column.name: getattr(row, column.name) for column in Analysis.__table__.columns if column.name != "user_id"}
    stamp = row.created_at.isoformat()
    result["created_at"] = stamp if row.created_at.tzinfo else stamp + "+00:00"
    return result
