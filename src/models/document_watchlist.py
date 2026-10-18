from sqlalchemy import Column, DateTime, String, func

from models.base import Base


class DocumentWatchlist(Base):
    __tablename__ = "document_watchlist"

    document_number = Column(String(18), primary_key=True)
    first_seen_at = Column(DateTime, nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime, nullable=False, server_default=func.now())
    last_checked_at = Column(DateTime, nullable=True)
