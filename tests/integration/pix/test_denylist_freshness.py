"""Denylist + freshness quente/frio — suite TDD red (tests-denylist-freshness).

Cenarios:
- documento ja em document_block → rejected (sem depender da mock)
- path frio consulta a mock; se condenado, rejeita
- path quente (Pix recente) nao chama a mock de novo
- timeout da mock no frio → fail-open (segue pro motor, flag no metadata)

A API no Docker precisa enxergar o mock via FRAUD_REGISTRY_API_URL
(ex.: http://host.docker.internal:8765). Enquanto a rota Pix nao existe,
tudo aqui fica vermelho — correto no TDD.
"""

from uuid import uuid4

from tests.utils import DbUtils, PayloadGenerator, RandomGenerator, RequestGenerator
from tests.utils.fraud_registry_mock import FraudRegistryMock


MOCK_PORT = 8765


def _pix_for_documents(source_document: str, dest_document: str, **overrides) -> dict:
    payload = PayloadGenerator.create_pix_transaction_payload(
        amount=15000,
        transaction_date="2026-10-17T14:15:00-03:00",
        source_account={
            "opening_date": "2020-03-02T10:00:00-03:00",
            "owner": {"document_number": source_document},
        },
        destination_account={
            "opening_date": "2020-10-10T09:00:00-03:00",
            "owner": {"document_number": dest_document},
        },
        source={
            "device_id": f"dvc-{uuid4().hex[:8]}",
            "channel": "app",
            "ip": "198.51.100.77",
        },
    )
    for key, value in overrides.items():
        payload[key] = value
    return payload


class TestDenylistFreshness:
    def test_rejects_when_source_document_is_blocked(self):
        source = RandomGenerator.generate_cpf()
        dest = RandomGenerator.generate_cpf()
        DbUtils.insert_document_block(source, reason="fraude conhecida")

        status, response = RequestGenerator.POST_pix_transaction(
            _pix_for_documents(source, dest)
        )

        assert status == 201
        assert response["status"] == "rejected"
        assert response["metadata"]["decision_reason"] == "document_blocked"
        assert source in response["metadata"].get("blocked_documents", [source])

    def test_rejects_when_destination_document_is_blocked(self):
        source = RandomGenerator.generate_cpf()
        dest = RandomGenerator.generate_cpf()
        DbUtils.insert_document_block(dest, reason="mule")

        status, response = RequestGenerator.POST_pix_transaction(
            _pix_for_documents(source, dest)
        )

        assert status == 201
        assert response["status"] == "rejected"
        assert response["metadata"]["decision_reason"] == "document_blocked"

    def test_cold_document_calls_registry_and_rejects_when_condemned(self):
        mock = FraudRegistryMock(port=MOCK_PORT)
        mock.start()
        try:
            source = RandomGenerator.generate_cpf()
            dest = RandomGenerator.generate_cpf()
            mock.condemn(dest)

            status, response = RequestGenerator.POST_pix_transaction(
                _pix_for_documents(source, dest)
            )

            assert status == 201
            assert response["status"] == "rejected"
            assert response["metadata"]["decision_reason"] == "document_blocked"
            assert dest in mock.hits
        finally:
            mock.stop()

    def test_hot_document_does_not_call_registry_again(self):
        """Segundo Pix na janela TTL: so le document_block local."""
        mock = FraudRegistryMock(port=MOCK_PORT)
        mock.start()
        try:
            source = RandomGenerator.generate_cpf()
            dest = RandomGenerator.generate_cpf()
            device_id = f"dvc-{uuid4().hex[:8]}"

            first = _pix_for_documents(
                source,
                dest,
                source={
                    "device_id": device_id,
                    "channel": "app",
                    "ip": "198.51.100.77",
                },
            )
            first_status, _ = RequestGenerator.POST_pix_transaction(first)
            assert first_status == 201
            hits_after_cold = list(mock.hits)
            assert len(hits_after_cold) >= 1

            mock.clear_hits()

            second = _pix_for_documents(
                source,
                dest,
                source={
                    "device_id": device_id,
                    "channel": "app",
                    "ip": "198.51.100.77",
                },
            )
            second_status, second_response = RequestGenerator.POST_pix_transaction(second)
            assert second_status == 201
            assert mock.hits == []
            assert second_response["metadata"].get("fraud_registry_check") != "cold_fetch"
        finally:
            mock.stop()

    def test_cold_registry_timeout_fails_open(self):
        """Mock lenta demais: nao rejeita por denylist; segue pro motor."""
        mock = FraudRegistryMock(port=MOCK_PORT)
        mock.delay_seconds = 2.0
        mock.start()
        try:
            source = RandomGenerator.generate_cpf()
            dest = RandomGenerator.generate_cpf()
            mock.condemn(source)

            status, response = RequestGenerator.POST_pix_transaction(
                _pix_for_documents(source, dest)
            )

            assert status == 201
            assert response["metadata"]["fraud_registry_check"] in {"timeout", "error"}
            assert response["metadata"]["decision_reason"] != "document_blocked"
        finally:
            mock.stop()
