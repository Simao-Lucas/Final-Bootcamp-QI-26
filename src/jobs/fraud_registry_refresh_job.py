"""Job periodico: refresca a denylist dos documentos quentes."""

from __future__ import annotations

import threading
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from connectors.fraud_registry_connector import FraudRegistryConnector
from constants import DATABASE_URL, FRAUD_CHECK_TTL_HOURS
from database import Context
from repositories import DocumentBlockRepository, DocumentWatchlistRepository
from services.document_freshness import DocumentFreshnessService
from utils.logger import get_logger

logger = get_logger(__name__)


def _run_once() -> None:
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        context = Context()
        context.db_session = session
        service = DocumentFreshnessService(
            DocumentWatchlistRepository(context),
            DocumentBlockRepository(context),
            FraudRegistryConnector(),
        )
        refreshed = service.refresh_hot_watchlist()
        session.commit()
        logger.info(f"Fraud registry job refreshed {refreshed} hot document(s)")
    except Exception:
        session.rollback()
        logger.exception("Fraud registry job failed")
    finally:
        session.close()
        engine.dispose()


def start_fraud_registry_refresh_job(stop_event: threading.Event) -> threading.Thread:
    """Dispara o job a cada TTL horas (minimo 60s pra nao martelar em teste)."""
    interval_seconds = max(60, int(FRAUD_CHECK_TTL_HOURS * 3600))

    def loop() -> None:
        # Primeira rodada depois de um pequeno atraso — deixa a API subir.
        if stop_event.wait(15):
            return
        while not stop_event.is_set():
            _run_once()
            if stop_event.wait(interval_seconds):
                break

    thread = threading.Thread(target=loop, name="fraud-registry-refresh", daemon=True)
    thread.start()
    return thread
