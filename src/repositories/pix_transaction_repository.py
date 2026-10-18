from datetime import datetime, timedelta
from uuid import uuid4

from database import Context
from models import PixTransaction


class PixTransactionRepository:
    def __init__(self, context: Context) -> None:
        self.session = context.db_session

    def get_by_pix_id(self, pix_id: str) -> PixTransaction | None:
        return (
            self.session.query(PixTransaction)
            .filter(PixTransaction.pix_id == pix_id)
            .first()
        )

    def create(
        self,
        *,
        pix_id: str,
        status: str,
        rule_set_id: int,
        triggered_mask: int,
        score: int,
        payload: dict,
        transaction_date: datetime,
        source_opening_date: datetime,
        dest_opening_date: datetime,
        metadata: dict,
    ) -> PixTransaction:
        source_account = payload["source_account"]
        destination_account = payload["destination_account"]
        source = payload["source"]
        geolocation = source.get("geolocation") or {}

        pix = PixTransaction()
        pix.analysis_key = str(uuid4())
        pix.pix_id = pix_id
        pix.status = status
        pix.rule_set_id = rule_set_id
        pix.triggered_mask = triggered_mask
        pix.score = score
        pix.amount = payload["amount"]
        pix.transaction_date = transaction_date
        pix.source_document = source_account["owner"]["document_number"]
        pix.source_branch = source_account["branch"]
        pix.source_account_number = source_account["account_number"]
        pix.source_opening_date = source_opening_date
        pix.dest_document = destination_account["owner"]["document_number"]
        pix.dest_participant = destination_account["participant"]
        pix.dest_branch = destination_account["branch"]
        pix.dest_account_number = destination_account["account_number"]
        pix.dest_opening_date = dest_opening_date
        pix.device_id = source["device_id"]
        pix.channel = source["channel"]
        pix.ip = source["ip"]
        pix.latitude = geolocation.get("latitude")
        pix.longitude = geolocation.get("longitude")
        pix.metadata_json = metadata

        self.session.add(pix)
        return pix

    def list_by_source_document(
        self, document_number: str, since: datetime | None = None
    ) -> list[PixTransaction]:
        query = self.session.query(PixTransaction).filter(
            PixTransaction.source_document == document_number
        )
        if since is not None:
            query = query.filter(PixTransaction.transaction_date >= since)
        return query.order_by(PixTransaction.transaction_date.asc()).all()

    def list_by_dest_document(
        self, document_number: str, since: datetime | None = None
    ) -> list[PixTransaction]:
        query = self.session.query(PixTransaction).filter(
            PixTransaction.dest_document == document_number
        )
        if since is not None:
            query = query.filter(PixTransaction.transaction_date >= since)
        return query.order_by(PixTransaction.transaction_date.asc()).all()

    def count_source_to_dest(self, source_document: str, dest_document: str) -> int:
        return (
            self.session.query(PixTransaction)
            .filter(
                PixTransaction.source_document == source_document,
                PixTransaction.dest_document == dest_document,
            )
            .count()
        )

    def count_rejects_for_dest(self, dest_document: str, since: datetime) -> int:
        return (
            self.session.query(PixTransaction)
            .filter(
                PixTransaction.dest_document == dest_document,
                PixTransaction.status == "rejected",
                PixTransaction.transaction_date >= since,
            )
            .count()
        )

    def has_recent_adverse_for_source(
        self, source_document: str, since: datetime
    ) -> bool:
        return (
            self.session.query(PixTransaction)
            .filter(
                PixTransaction.source_document == source_document,
                PixTransaction.status.in_(["rejected", "two_factor_required"]),
                PixTransaction.transaction_date >= since,
            )
            .first()
            is not None
        )

    def count_distinct_devices_for_device(
        self, device_id: str, since: datetime
    ) -> int:
        rows = (
            self.session.query(PixTransaction.source_document)
            .filter(
                PixTransaction.device_id == device_id,
                PixTransaction.transaction_date >= since,
            )
            .distinct()
            .all()
        )
        return len(rows)
