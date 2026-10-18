from sqlalchemy import Column, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from models.base import Base


class DocumentBlock(Base):
    __tablename__ = "document_block"

    document_number = Column(String(18), primary_key=True)
    reason = Column(Text, nullable=False)
    source = Column(String(64), nullable=False)
    raw_payload = Column(JSONB, nullable=False, default=dict)
    blocked_at = Column(DateTime, nullable=False, server_default=func.now())
    last_checked_at = Column(DateTime, nullable=False, server_default=func.now())
