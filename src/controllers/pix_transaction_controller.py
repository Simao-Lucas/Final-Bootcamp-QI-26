from datetime import datetime

from controllers.base_controller import BaseController
from dtos import PixTransactionDTO
from errors import NotFoundPixTransaction
from repositories import (
    DocumentBlockRepository,
    DocumentWatchlistRepository,
    FraudRuleSetRepository,
    PixTransactionRepository,
)
from services.document_freshness import DocumentFreshnessService
from utils.fraud_engine import FraudEngine, build_evaluation_context


class PixTransactionController(BaseController):
    def __init__(self) -> None:
        super().__init__(__name__)
        self.pix_repository = PixTransactionRepository(self.context)
        self.rule_set_repository = FraudRuleSetRepository(self.context)
        self.block_repository = DocumentBlockRepository(self.context)
        self.watchlist_repository = DocumentWatchlistRepository(self.context)
        self.fraud_engine = FraudEngine(self.pix_repository)
        self.freshness_service = DocumentFreshnessService(
            self.watchlist_repository,
            self.block_repository,
        )

    def analyze(self, payload: dict) -> dict:
        existing = self.pix_repository.get_by_pix_id(payload["id"])
        if existing is not None:
            return PixTransactionDTO.analysis_response(existing)

        transaction_date = self._parse_datetime(payload["transaction_date"])
        source_opening_date = self._parse_datetime(payload["source_account"]["opening_date"])
        dest_opening_date = self._parse_datetime(
            payload["destination_account"]["opening_date"]
        )
        source_document = payload["source_account"]["owner"]["document_number"]
        dest_document = payload["destination_account"]["owner"]["document_number"]
        documents = [source_document, dest_document]

        freshness_meta = self.freshness_service.refresh_documents(documents)
        checked_documents = set(freshness_meta.pop("checked_documents", []) or [])

        blocked_documents = [
            document_number
            for document_number in documents
            if self.block_repository.get(document_number) is not None
        ]

        rule_set = self.rule_set_repository.get_active()

        if blocked_documents:
            status = "rejected"
            triggered_mask = 0
            score = 0
            metadata = {
                "rule_set_version": rule_set.version,
                "triggered_mask": 0,
                "triggered_rules": [],
                "score": 0,
                "score_threshold_2fa": rule_set.score_threshold_2fa,
                "decision_reason": "document_blocked",
                "matched_pattern": None,
                "blocked_documents": blocked_documents,
                **freshness_meta,
            }
            rule_set_id = rule_set.id
        else:
            source_history = self.pix_repository.list_by_source_document(source_document)
            dest_history = self.pix_repository.list_by_dest_document(dest_document)
            context = build_evaluation_context(
                payload,
                transaction_date,
                source_opening_date,
                dest_opening_date,
                source_history,
                dest_history,
            )
            decision = self.fraud_engine.evaluate(rule_set, context)
            status = decision["status"]
            triggered_mask = decision["triggered_mask"]
            score = decision["score"]
            metadata = {**decision["metadata"], **freshness_meta}
            rule_set_id = rule_set.id

        pix = self.pix_repository.create(
            pix_id=payload["id"],
            status=status,
            rule_set_id=rule_set_id,
            triggered_mask=triggered_mask,
            score=score,
            payload=payload,
            transaction_date=transaction_date,
            source_opening_date=source_opening_date,
            dest_opening_date=dest_opening_date,
            metadata=metadata,
        )

        # last_seen usa relogio de parede: a janela quente/frio e "ultimas Xh
        # reais", nao a data do Pix do payload (que nos testes e fixa).
        # Um unico caminho de escrita na watchlist evita UniqueViolation.
        seen_at = datetime.now()
        for document_number in documents:
            entry = self.watchlist_repository.upsert_seen(document_number, seen_at)
            if document_number in checked_documents:
                entry.last_checked_at = seen_at

        self.session.commit()
        return PixTransactionDTO.analysis_response(pix)

    def get_by_pix_id(self, pix_id: str) -> dict:
        pix = self.pix_repository.get_by_pix_id(pix_id)
        if pix is None:
            raise NotFoundPixTransaction(pix_id)
        return PixTransactionDTO.analysis_response(pix)

    def _parse_datetime(self, raw_value: str) -> datetime:
        parsed = datetime.fromisoformat(raw_value)
        if parsed.tzinfo is not None:
            parsed = parsed.replace(tzinfo=None)
        return parsed
