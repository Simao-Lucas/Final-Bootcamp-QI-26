"""Freshness da denylist: docs frios consultam a mock; quentes so leem o cache local."""

from __future__ import annotations

from datetime import datetime, timedelta

from connectors.fraud_registry_connector import FraudRegistryConnector
from constants import FRAUD_CHECK_TTL_HOURS
from repositories import DocumentBlockRepository, DocumentWatchlistRepository


class DocumentFreshnessService:
    def __init__(
        self,
        watchlist_repository: DocumentWatchlistRepository,
        block_repository: DocumentBlockRepository,
        registry_connector: FraudRegistryConnector | None = None,
    ) -> None:
        self.watchlist_repository = watchlist_repository
        self.block_repository = block_repository
        self.registry_connector = registry_connector or FraudRegistryConnector()
        self.ttl = timedelta(hours=FRAUD_CHECK_TTL_HOURS)

    def is_hot(self, document_number: str, now: datetime | None = None) -> bool:
        now = now or datetime.now()
        entry = self.watchlist_repository.get(document_number)
        if entry is None or entry.last_seen_at is None:
            return False
        return entry.last_seen_at >= now - self.ttl

    def refresh_documents(self, document_numbers: list[str]) -> dict:
        """Atualiza docs frios via mock. Retorna metadados do check.

        Nao escreve na watchlist — o controller marca last_seen no final.
        So atualiza document_block e devolve quais docs foram checados com sucesso.
        """
        now = datetime.now()
        check_flags: list[str] = []
        cold_fetched = False
        checked_documents: list[str] = []

        for document_number in document_numbers:
            if self.is_hot(document_number, now):
                check_flags.append("hot_skip")
                continue

            cold_fetched = True
            result = self.registry_connector.check_document(document_number)
            if not result["ok"]:
                check_flags.append(result["error"])
                continue

            check_flags.append("cold_fetch")
            checked_documents.append(document_number)
            if result["condemned"]:
                self.block_repository.upsert(
                    document_number=document_number,
                    reason="condenado na API de registro de fraude",
                    source="mock_api",
                    raw_payload=result.get("payload") or {},
                )
            else:
                self.block_repository.delete(document_number)

        if "timeout" in check_flags:
            fraud_registry_check = "timeout"
        elif "error" in check_flags:
            fraud_registry_check = "error"
        elif cold_fetched:
            fraud_registry_check = "cold_fetch"
        else:
            fraud_registry_check = "hot_skip"

        return {
            "fraud_registry_check": fraud_registry_check,
            "checked_documents": checked_documents,
        }

    def refresh_hot_watchlist(self) -> int:
        """Job: reconsulta so documentos com last_seen nas ultimas X horas."""
        now = datetime.now()
        hot_docs = self.watchlist_repository.list_hot(now - self.ttl)
        refreshed = 0
        for entry in hot_docs:
            result = self.registry_connector.check_document(entry.document_number)
            if not result["ok"]:
                continue
            self.watchlist_repository.mark_checked(entry.document_number, now)
            if result["condemned"]:
                self.block_repository.upsert(
                    document_number=entry.document_number,
                    reason="condenado na API de registro de fraude",
                    source="mock_api",
                    raw_payload=result.get("payload") or {},
                )
            else:
                self.block_repository.delete(entry.document_number)
            refreshed += 1
        return refreshed
