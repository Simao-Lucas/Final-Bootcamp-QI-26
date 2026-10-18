"""Motor de decisao — suite TDD red (tests-fraud-engine).

Foca na matematica: submascara de pattern (exato e superset), bit
faltando nao rejeita, score >= limiar pede 2FA, score baixo aprova.
Reject so por pattern (ou denylist). Seed v1: threshold 2FA 40.
"""

import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from services.fraud_engine import decide_status

from tests.utils import PayloadGenerator, RandomGenerator, RequestGenerator


def _stable_identity():
    """Mesmo pagador/destino/device/ip — serve pra montar historico via API."""
    return {
        "source_document": RandomGenerator.generate_cpf(),
        "dest_document": RandomGenerator.generate_cpf(),
        "device_id": f"dvc-{uuid4().hex[:8]}",
        "ip": "203.0.113.50",
    }


def _payload_with_identity(identity: dict, **overrides) -> dict:
    base = {
        "source_account": {
            "opening_date": "2020-03-02T10:00:00-03:00",
            "owner": {"document_number": identity["source_document"]},
        },
        "destination_account": {
            "opening_date": "2020-10-10T09:00:00-03:00",
            "owner": {"document_number": identity["dest_document"]},
        },
        "source": {
            "device_id": identity["device_id"],
            "channel": "app",
            "ip": identity["ip"],
            "geolocation": {"latitude": -23.56, "longitude": -46.65},
        },
        "amount": 15000,
        "transaction_date": "2026-10-17T14:15:00-03:00",
    }
    base.update(overrides)
    return PayloadGenerator.create_pix_transaction_payload(**base)


class TestFraudEngineDecision:
    def test_rejects_when_exact_critical_pattern_matches(self):
        """CEILING_AND_NEW_DEST: bits 18 + 6 exatamente o necessario."""
        payload = PayloadGenerator.create_pix_transaction_payload(
            amount=6_000_000,
            transaction_date="2026-10-17T14:15:00-03:00",
            source_account={"opening_date": "2020-03-02T10:00:00-03:00"},
            destination_account={"opening_date": "2026-10-15T09:00:00-03:00"},
        )

        status, response = RequestGenerator.POST_pix_transaction(payload)
        assert status == 201
        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "CEILING_AND_NEW_DEST"
        assert "AMOUNT_HARD_CEILING" in response["metadata"]["triggered_rules"]
        assert "NEW_DEST_ACCOUNT" in response["metadata"]["triggered_rules"]

    def test_rejects_when_triggered_is_superset_of_critical_pattern(self):
        """Pattern 10011 rejeita 11011: bits a mais nao salvam o Pix.

        CEILING + NEW_DEST + ATYPICAL_HOUR (bit 11 extra) ainda casa
        CEILING_AND_NEW_DEST.
        """
        payload = PayloadGenerator.create_pix_transaction_payload(
            amount=6_000_000,
            transaction_date="2026-10-17T02:30:00-03:00",
            source_account={"opening_date": "2020-03-02T10:00:00-03:00"},
            destination_account={"opening_date": "2026-10-15T09:00:00-03:00"},
        )

        status, response = RequestGenerator.POST_pix_transaction(payload)
        assert status == 201
        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "CEILING_AND_NEW_DEST"
        assert "ATYPICAL_HOUR" in response["metadata"]["triggered_rules"]

    def test_does_not_reject_when_critical_pattern_bit_is_missing(self):
        """So o teto absoluto, conta destino antiga: falta bit 6 do pattern.

        Pode pedir 2FA por score, mas nao rejeita por CEILING_AND_NEW_DEST.
        """
        payload = PayloadGenerator.create_pix_transaction_payload(
            amount=6_000_000,
            transaction_date="2026-10-17T14:15:00-03:00",
            source_account={"opening_date": "2020-03-02T10:00:00-03:00"},
            destination_account={"opening_date": "2020-10-10T09:00:00-03:00"},
        )

        status, response = RequestGenerator.POST_pix_transaction(payload)
        assert status == 201
        assert response["status"] != "rejected"
        assert response["metadata"].get("matched_pattern") is None
        assert "AMOUNT_HARD_CEILING" in response["metadata"]["triggered_rules"]
        assert "NEW_DEST_ACCOUNT" not in response["metadata"]["triggered_rules"]

    def test_two_factor_when_score_reaches_threshold_without_pattern(self):
        """Score >= 40 e nenhum pattern → two_factor_required.

        Depois de um Pix previo com o mesmo device/ip, UNKNOWN_DEVICE e
        UNKNOWN_IP deixam de disparar; NEW_SOURCE + NEW_DEST + UNKNOWN_DEST
        + ATYPICAL_HOUR somam 40 sem casar pattern seed.
        """
        identity = _stable_identity()

        priming = _payload_with_identity(
            identity,
            amount=10000,
            transaction_date="2026-10-17T10:00:00-03:00",
        )
        priming_status, _ = RequestGenerator.POST_pix_transaction(priming)
        assert priming_status == 201

        risky = _payload_with_identity(
            identity,
            amount=20000,
            transaction_date="2026-10-17T02:15:00-03:00",
            source_account={
                "opening_date": "2026-09-20T10:00:00-03:00",
                "owner": {"document_number": identity["source_document"]},
            },
            destination_account={
                "opening_date": "2026-10-12T09:00:00-03:00",
                "owner": {"document_number": RandomGenerator.generate_cpf()},
            },
        )

        status, response = RequestGenerator.POST_pix_transaction(risky)
        assert status == 201
        assert response["status"] == "two_factor_required"
        assert response["metadata"]["score"] >= 40
        assert response["metadata"].get("matched_pattern") is None
        assert response["metadata"]["score_threshold_2fa"] == 40

    def test_approved_when_score_below_threshold(self):
        """Historico estabiliza device/ip/destino; Pix calmo fica abaixo de 40."""
        identity = _stable_identity()

        for hour in ("10:00:00", "11:00:00", "12:00:00"):
            priming = _payload_with_identity(
                identity,
                amount=10000,
                transaction_date=f"2026-10-16T{hour}-03:00",
            )
            priming_status, _ = RequestGenerator.POST_pix_transaction(priming)
            assert priming_status == 201

        calm = _payload_with_identity(
            identity,
            amount=12000,
            transaction_date="2026-10-17T14:15:00-03:00",
        )

        status, response = RequestGenerator.POST_pix_transaction(calm)
        assert status == 201
        assert response["status"] == "approved"
        assert response["metadata"]["score"] < 40
        assert response["metadata"].get("matched_pattern") is None

    def test_metadata_exposes_triggered_mask_and_rule_set_version(self):
        payload = PayloadGenerator.create_pix_transaction_payload(amount=15000)

        status, response = RequestGenerator.POST_pix_transaction(payload)
        assert status == 201
        metadata = response["metadata"]
        assert metadata["rule_set_version"] == 1
        assert metadata["score_threshold_2fa"] == 40
        assert "score_threshold_reject" not in metadata
        assert "triggered_mask" in metadata
        assert "triggered_rules" in metadata
        assert isinstance(metadata["triggered_rules"], list)
        assert "score" in metadata
        assert "decision_reason" in metadata

    def test_high_score_without_pattern_asks_two_factor_not_reject(self):
        status, reason, matched = decide_status(
            triggered_mask=0,
            score=200,
            patterns=[],
            score_threshold_2fa=40,
        )

        assert status == "two_factor_required"
        assert reason == "score_above_threshold"
        assert matched is None

    def test_critical_pattern_rejects_regardless_of_score(self):
        pattern = SimpleNamespace(id=1, code="UNIT_PATTERN", pattern_mask=0b101)

        status, reason, matched = decide_status(
            triggered_mask=0b101,
            score=200,
            patterns=[pattern],
            score_threshold_2fa=40,
        )

        assert status == "rejected"
        assert reason == "critical_pattern_matched"
        assert matched is pattern
