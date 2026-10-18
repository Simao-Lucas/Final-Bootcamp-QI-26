from datetime import datetime

from database import Context
from models import DocumentBlock


class DocumentBlockRepository:
    def __init__(self, context: Context) -> None:
        self.session = context.db_session

    def get(self, document_number: str) -> DocumentBlock | None:
        """Busca por PK, incluindo objetos pending (autoflush=False)."""
        for obj in self.session.new:
            if isinstance(obj, DocumentBlock) and obj.document_number == document_number:
                return obj
        return self.session.get(DocumentBlock, document_number)

    def upsert(
        self,
        document_number: str,
        reason: str,
        source: str,
        raw_payload: dict,
    ) -> DocumentBlock:
        block = self.get(document_number)
        now = datetime.now()
        if block is None:
            block = DocumentBlock(
                document_number=document_number,
                blocked_at=now,
                reason=reason,
                source=source,
                raw_payload=raw_payload,
                last_checked_at=now,
            )
            self.session.add(block)
            return block

        block.reason = reason
        block.source = source
        block.raw_payload = raw_payload
        block.last_checked_at = now
        return block

    def delete(self, document_number: str) -> None:
        block = self.get(document_number)
        if block is not None:
            self.session.delete(block)
