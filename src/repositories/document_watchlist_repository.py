from datetime import datetime

from database import Context
from models import DocumentWatchlist


class DocumentWatchlistRepository:
    def __init__(self, context: Context) -> None:
        self.session = context.db_session

    def get(self, document_number: str) -> DocumentWatchlist | None:
        """Busca por PK, incluindo objetos pending (autoflush=False)."""
        for obj in self.session.new:
            if isinstance(obj, DocumentWatchlist) and obj.document_number == document_number:
                return obj
        return self.session.get(DocumentWatchlist, document_number)

    def upsert_seen(self, document_number: str, seen_at: datetime | None = None) -> DocumentWatchlist:
        now = seen_at or datetime.now()
        entry = self.get(document_number)
        if entry is None:
            entry = DocumentWatchlist(
                document_number=document_number,
                first_seen_at=now,
                last_seen_at=now,
            )
            self.session.add(entry)
        else:
            entry.last_seen_at = now
        return entry

    def mark_checked(self, document_number: str, checked_at: datetime | None = None) -> DocumentWatchlist:
        """Garante a linha e atualiza last_checked_at (e last_seen_at)."""
        now = checked_at or datetime.now()
        entry = self.upsert_seen(document_number, now)
        entry.last_checked_at = now
        return entry

    def list_hot(self, since: datetime) -> list[DocumentWatchlist]:
        return (
            self.session.query(DocumentWatchlist)
            .filter(DocumentWatchlist.last_seen_at >= since)
            .all()
        )
