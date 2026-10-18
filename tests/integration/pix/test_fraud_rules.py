"""Regras do rule_set v1: correcoes de bug, padroes criticos e falsos positivos.

Cada cenario usa pagador, destino, device e IP aleatorios, entao nao
depende do que outros testes deixaram no banco.
"""

from random import randint
from uuid import uuid4

from tests.utils import PayloadGenerator, RandomGenerator, RequestGenerator


def _random_ip(first_octet: int = 10) -> str:
    return f"{first_octet}.{randint(0, 255)}.{randint(0, 255)}.{randint(1, 254)}"


def _identity() -> dict:
    return {
        "source_document": RandomGenerator.generate_cpf(),
        "dest_document": RandomGenerator.generate_cpf(),
        "device_id": f"dvc-{uuid4().hex[:8]}",
        "ip": _random_ip(),
    }


def _pix(identity: dict, **overrides) -> dict:
    base = {
        "amount": 15000,
        "transaction_date": "2026-10-17T14:15:00-03:00",
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
    }
    base.update(overrides)
    return PayloadGenerator.create_pix_transaction_payload(**base)


def _post(payload: dict) -> dict:
    status, response = RequestGenerator.POST_pix_transaction(payload)
    assert status == 201
    return response


def _prime_profile(identity: dict) -> None:
    """Cinco Pix de R$ 1.000 em dias distintos: perfil com mediana conhecida."""
    for day in range(10, 15):
        priming = _post(
            _pix(
                identity,
                amount=100000,
                transaction_date=f"2026-10-{day}T14:00:00-03:00",
            )
        )
        assert priming["status"] == "approved"


class TestFraudRules:
    def test_own_device_is_not_shared_device(self):
        identity = _identity()
        _post(_pix(identity, transaction_date="2026-10-17T10:00:00-03:00"))

        response = _post(_pix(identity, transaction_date="2026-10-17T11:00:00-03:00"))

        assert "SHARED_DEVICE" not in response["metadata"]["triggered_rules"]

    def test_rejected_attempt_does_not_make_device_known(self):
        identity = _identity()
        assert _post(
            _pix(identity, transaction_date="2026-10-17T10:00:00-03:00")
        )["status"] == "approved"

        attacker = {**identity, "device_id": f"dvc-{uuid4().hex[:8]}"}
        rejected = _post(
            _pix(
                attacker,
                amount=6_000_000,
                transaction_date="2026-10-17T10:05:00-03:00",
                destination_account={
                    "opening_date": "2026-10-15T09:00:00-03:00",
                    "owner": {"document_number": RandomGenerator.generate_cpf()},
                },
            )
        )
        assert rejected["status"] == "rejected"

        retry = _post(_pix(attacker, transaction_date="2026-10-17T10:10:00-03:00"))

        assert "UNKNOWN_DEVICE" in retry["metadata"]["triggered_rules"]
        assert "REPEAT_AFTER_REJECT" in retry["metadata"]["triggered_rules"]

    def test_new_phone_is_not_stuck_in_two_factor(self):
        identity = _identity()
        _post(_pix(identity, transaction_date="2026-10-17T10:00:00-03:00"))

        new_phone = {**identity, "device_id": f"dvc-{uuid4().hex[:8]}", "ip": _random_ip(172)}
        first = _post(_pix(new_phone, transaction_date="2026-10-17T10:30:00-03:00"))
        assert first["status"] == "two_factor_required"

        second = _post(_pix(new_phone, transaction_date="2026-10-17T10:40:00-03:00"))

        assert "UNKNOWN_DEVICE" not in second["metadata"]["triggered_rules"]
        assert second["status"] == "approved"

    def test_utc_timestamp_is_evaluated_in_brasilia_time(self):
        night_in_brasilia = _post(
            _pix(_identity(), transaction_date="2026-10-17T05:30:00Z")
        )
        evening_in_brasilia = _post(
            _pix(_identity(), transaction_date="2026-10-17T02:30:00Z")
        )

        assert "ATYPICAL_HOUR" in night_in_brasilia["metadata"]["triggered_rules"]
        assert "ATYPICAL_HOUR" not in evening_in_brasilia["metadata"]["triggered_rules"]

    def test_single_high_pix_does_not_fire_velocity_sum(self):
        response = _post(_pix(_identity(), amount=2_000_000))

        assert "VELOCITY_SUM" not in response["metadata"]["triggered_rules"]

    def test_splitting_fires_with_three_parts(self):
        identity = _identity()
        for minute in ("10:00", "10:10"):
            _post(
                _pix(
                    identity,
                    amount=90000,
                    transaction_date=f"2026-10-17T{minute}:00-03:00",
                )
            )

        response = _post(
            _pix(identity, amount=90000, transaction_date="2026-10-17T10:20:00-03:00")
        )

        assert "AMOUNT_SPLITTING" in response["metadata"]["triggered_rules"]

    def test_account_takeover_pattern_rejects(self):
        identity = _identity()
        _prime_profile(identity)

        takeover = {
            "source_document": identity["source_document"],
            "dest_document": RandomGenerator.generate_cpf(),
            "device_id": f"dvc-{uuid4().hex[:8]}",
            "ip": _random_ip(172),
        }
        response = _post(
            _pix(takeover, amount=500000, transaction_date="2026-10-17T14:00:00-03:00")
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "ACCOUNT_TAKEOVER"

    def test_new_phone_on_home_network_gets_two_factor_not_reject(self):
        """Device novo, mesma rede, valor alto para destino novo: 2FA."""
        identity = _identity()
        _prime_profile(identity)

        new_phone = {
            **identity,
            "dest_document": RandomGenerator.generate_cpf(),
            "device_id": f"dvc-{uuid4().hex[:8]}",
        }
        response = _post(
            _pix(new_phone, amount=500000, transaction_date="2026-10-17T14:00:00-03:00")
        )

        assert response["status"] == "two_factor_required"
        assert response["metadata"]["matched_pattern"] is None

    def test_hard_ceiling_follows_high_spender_profile(self):
        """Quem ja movimenta R$ 100 mil nao cai no teto ate passar de 1,5x isso."""
        identity = _identity()
        for day in range(10, 15):
            _post(
                _pix(
                    identity,
                    amount=10_000_000,
                    transaction_date=f"2026-10-{day}T14:00:00-03:00",
                )
            )

        within_profile = _post(
            _pix(identity, amount=12_000_000, transaction_date="2026-10-15T14:00:00-03:00")
        )
        beyond_profile = _post(
            _pix(identity, amount=20_000_000, transaction_date="2026-10-16T14:00:00-03:00")
        )

        assert "AMOUNT_HARD_CEILING" not in within_profile["metadata"]["triggered_rules"]
        assert within_profile["status"] == "approved"
        assert "AMOUNT_HARD_CEILING" in beyond_profile["metadata"]["triggered_rules"]

    def test_out_of_profile_tolerates_naturally_variable_payer(self):
        """Paga de R$ 100 a R$ 8.000: R$ 5.000 e 5x a mediana, mas normal para ele."""
        identity = _identity()
        for day, amount in zip(range(1, 6), (10000, 30000, 100000, 300000, 800000)):
            _post(
                _pix(
                    identity,
                    amount=amount,
                    transaction_date=f"2026-10-0{day}T14:00:00-03:00",
                )
            )

        response = _post(_pix(identity, amount=500000))

        assert "AMOUNT_OUT_OF_PROFILE" not in response["metadata"]["triggered_rules"]

    def test_out_of_profile_uses_destination_type_profile(self):
        """Paga boletos altos a CNPJ e Pix pequenos a CPF: cada lado tem sua regua."""
        identity = _identity()
        company = {**identity, "dest_document": RandomGenerator.generate_cnpj()}
        for day in range(1, 6):
            _post(
                _pix(
                    company,
                    amount=300000,
                    transaction_date=f"2026-10-0{day}T10:00:00-03:00",
                )
            )
            _post(
                _pix(
                    identity,
                    amount=10000,
                    transaction_date=f"2026-10-0{day}T18:00:00-03:00",
                )
            )

        to_person = _post(_pix(identity, amount=250000))
        to_company = _post(_pix(company, amount=350000))

        assert "AMOUNT_OUT_OF_PROFILE" in to_person["metadata"]["triggered_rules"]
        assert "AMOUNT_OUT_OF_PROFILE" not in to_company["metadata"]["triggered_rules"]

    def test_cold_start_covers_payer_without_full_profile(self):
        """Com 3 Pix ainda nao ha perfil (minimo 5): o cold start avalia o valor."""
        identity = _identity()
        for day in range(10, 13):
            _post(
                _pix(
                    identity,
                    amount=15000,
                    transaction_date=f"2026-10-{day}T14:00:00-03:00",
                )
            )

        response = _post(_pix(identity, amount=500000))

        assert "COLD_START_HIGH_AMOUNT" in response["metadata"]["triggered_rules"]
        assert "AMOUNT_OUT_OF_PROFILE" not in response["metadata"]["triggered_rules"]

    def test_hard_ceiling_uses_higher_floor_for_cnpj(self):
        identity = {**_identity(), "source_document": RandomGenerator.generate_cnpj()}

        response = _post(_pix(identity, amount=6_000_000))

        assert "AMOUNT_HARD_CEILING" not in response["metadata"]["triggered_rules"]

    def test_high_amount_to_known_new_account_is_not_rejected(self):
        """Segundo Pix alto para conta recente ja paga antes: nao e primeira vez."""
        identity = _identity()
        new_account = {
            "opening_date": "2026-10-15T09:00:00-03:00",
            "owner": {"document_number": identity["dest_document"]},
        }
        _post(
            _pix(
                identity,
                transaction_date="2026-10-16T10:00:00-03:00",
                destination_account=new_account,
            )
        )

        response = _post(
            _pix(
                identity,
                amount=6_000_000,
                transaction_date="2026-10-17T10:00:00-03:00",
                destination_account=new_account,
            )
        )

        assert response["status"] != "rejected"
        assert "AMOUNT_HARD_CEILING" in response["metadata"]["triggered_rules"]
