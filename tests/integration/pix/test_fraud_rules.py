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

    def test_pass_through_fires_when_forwarding_recent_inbound(self):
        mule = _identity()
        feeder = _identity()
        _post(
            _pix(
                feeder,
                amount=200000,
                transaction_date="2026-10-17T10:00:00-03:00",
                destination_account={
                    "opening_date": "2020-10-10T09:00:00-03:00",
                    "owner": {"document_number": mule["source_document"]},
                },
            )
        )

        response = _post(
            _pix(mule, amount=180000, transaction_date="2026-10-17T10:30:00-03:00")
        )

        assert "PASS_THROUGH" in response["metadata"]["triggered_rules"]

    def test_pass_through_and_new_source_pattern_rejects(self):
        mule = _identity()
        feeder = _identity()
        _post(
            _pix(
                feeder,
                amount=200000,
                transaction_date="2026-10-17T10:00:00-03:00",
                destination_account={
                    "opening_date": "2020-10-10T09:00:00-03:00",
                    "owner": {"document_number": mule["source_document"]},
                },
            )
        )

        response = _post(
            _pix(
                mule,
                amount=180000,
                transaction_date="2026-10-17T10:30:00-03:00",
                source_account={
                    "opening_date": "2026-09-20T10:00:00-03:00",
                    "owner": {"document_number": mule["source_document"]},
                },
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "PASS_THROUGH_AND_NEW_SOURCE"

    def test_night_high_amount_for_cpf_not_cnpj(self):
        person = _post(
            _pix(_identity(), amount=150000, transaction_date="2026-10-17T21:30:00-03:00")
        )
        company = _post(
            _pix(
                {**_identity(), "source_document": RandomGenerator.generate_cnpj()},
                amount=150000,
                transaction_date="2026-10-17T21:30:00-03:00",
            )
        )

        assert "NIGHT_HIGH_AMOUNT" in person["metadata"]["triggered_rules"]
        assert "NIGHT_HIGH_AMOUNT" not in company["metadata"]["triggered_rules"]

    def test_dormant_reactivation_after_idle_period(self):
        identity = _identity()
        _post(_pix(identity, transaction_date="2026-07-01T14:00:00-03:00"))

        response = _post(_pix(identity, transaction_date="2026-10-17T14:00:00-03:00"))

        assert "DORMANT_REACTIVATION" in response["metadata"]["triggered_rules"]

    def test_dormant_and_unknown_device_pattern_rejects(self):
        identity = _identity()
        _prime_profile(identity)

        response = _post(
            _pix(
                {
                    **identity,
                    "device_id": f"dvc-{uuid4().hex[:8]}",
                    "ip": _random_ip(172),
                },
                amount=500000,
                transaction_date="2027-01-20T14:00:00-03:00",
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "DORMANT_AND_UNKNOWN_DEVICE"
        assert "DORMANT_REACTIVATION" in response["metadata"]["triggered_rules"]

    def test_missing_geolocation_when_habitually_present(self):
        identity = _identity()
        _prime_profile(identity)

        payload = _pix(identity, transaction_date="2026-10-17T14:00:00-03:00")
        del payload["source"]["geolocation"]
        response = _post(payload)

        assert "MISSING_GEOLOCATION" in response["metadata"]["triggered_rules"]

    def test_shared_ip_across_many_payers(self):
        shared_ip = _random_ip(203)
        for _ in range(5):
            _post(
                _pix(
                    {**_identity(), "ip": shared_ip},
                    transaction_date="2026-10-17T10:00:00-03:00",
                )
            )

        response = _post(
            _pix(
                {**_identity(), "ip": shared_ip},
                transaction_date="2026-10-17T11:00:00-03:00",
            )
        )

        assert "SHARED_IP" in response["metadata"]["triggered_rules"]

    def test_implausible_geo_impossible_travel(self):
        identity = _identity()
        _post(
            _pix(
                identity,
                transaction_date="2026-10-17T10:00:00-03:00",
                source={
                    "device_id": identity["device_id"],
                    "channel": "app",
                    "ip": identity["ip"],
                    "geolocation": {"latitude": -23.56, "longitude": -46.65},
                },
            )
        )

        response = _post(
            _pix(
                identity,
                transaction_date="2026-10-17T10:30:00-03:00",
                source={
                    "device_id": identity["device_id"],
                    "channel": "app",
                    "ip": identity["ip"],
                    "geolocation": {"latitude": -8.05, "longitude": -34.88},
                },
            )
        )

        assert "IMPLAUSIBLE_GEO" in response["metadata"]["triggered_rules"]

    def test_unknown_ip_uses_prefix_not_exact_address(self):
        identity = {**_identity(), "ip": "198.51.100.10"}
        _post(_pix(identity, transaction_date="2026-10-17T10:00:00-03:00"))

        same_block = _post(
            _pix(
                {**identity, "ip": "198.51.100.200"},
                transaction_date="2026-10-17T11:00:00-03:00",
            )
        )
        other_block = _post(
            _pix(
                {**identity, "ip": "198.51.101.10"},
                transaction_date="2026-10-17T12:00:00-03:00",
            )
        )

        assert "UNKNOWN_IP" not in same_block["metadata"]["triggered_rules"]
        assert "UNKNOWN_IP" in other_block["metadata"]["triggered_rules"]

    def test_mule_forwarding_pattern_rejects(self):
        """Conta nova fracionando para muitos destinos JA conhecidos.

        Precisa de destino conhecido para nao casar antes
        SPLITTING_AND_MANY_ACCOUNTS (que exige UNKNOWN_DEST).
        """
        identity = _identity()
        old_source = {
            "opening_date": "2020-03-02T10:00:00-03:00",
            "owner": {"document_number": identity["source_document"]},
        }
        new_source = {
            "opening_date": "2026-09-20T10:00:00-03:00",
            "owner": {"document_number": identity["source_document"]},
        }
        destinations = [RandomGenerator.generate_cpf() for _ in range(5)]
        for index, dest in enumerate(destinations):
            _post(
                _pix(
                    {**identity, "dest_document": dest},
                    amount=10000,
                    transaction_date=f"2026-10-17T09:{index:02d}:00-03:00",
                    source_account=old_source,
                )
            )

        for index, dest in enumerate(destinations[:-1]):
            _post(
                _pix(
                    {**identity, "dest_document": dest},
                    amount=90000,
                    transaction_date=f"2026-10-17T10:{index:02d}:00-03:00",
                    source_account=new_source,
                )
            )

        response = _post(
            _pix(
                {**identity, "dest_document": destinations[-1]},
                amount=90000,
                transaction_date="2026-10-17T10:05:00-03:00",
                source_account=new_source,
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "MULE_FORWARDING"
        assert "NEW_SOURCE_ACCOUNT" in response["metadata"]["triggered_rules"]
        assert "AMOUNT_SPLITTING" in response["metadata"]["triggered_rules"]
        assert "PAYER_MANY_ACCOUNTS" in response["metadata"]["triggered_rules"]

    def test_repeat_after_2fa_fires_without_locking_device(self):
        identity = _identity()
        _post(_pix(identity, transaction_date="2026-10-17T10:00:00-03:00"))

        new_phone = {**identity, "device_id": f"dvc-{uuid4().hex[:8]}", "ip": _random_ip(172)}
        first = _post(_pix(new_phone, transaction_date="2026-10-17T10:30:00-03:00"))
        assert first["status"] == "two_factor_required"

        second = _post(_pix(new_phone, transaction_date="2026-10-17T10:40:00-03:00"))

        assert "REPEAT_AFTER_2FA" in second["metadata"]["triggered_rules"]
        assert "UNKNOWN_DEVICE" not in second["metadata"]["triggered_rules"]
        assert second["status"] == "approved"

    def test_velocity_sum_and_unknown_device_pattern_rejects(self):
        identity = _identity()
        _post(_pix(identity, amount=400000, transaction_date="2026-10-17T10:00:00-03:00"))
        _post(_pix(identity, amount=400000, transaction_date="2026-10-17T10:10:00-03:00"))

        response = _post(
            _pix(
                {
                    **identity,
                    "device_id": f"dvc-{uuid4().hex[:8]}",
                    "dest_document": RandomGenerator.generate_cpf(),
                },
                amount=400000,
                transaction_date="2026-10-17T10:20:00-03:00",
            )
        )

        assert response["status"] == "rejected"
        assert (
            response["metadata"]["matched_pattern"] == "VELOCITY_SUM_AND_UNKNOWN_DEVICE"
        )

    def test_velocity_count_fires_on_burst(self):
        identity = _identity()
        for minute in range(4):
            _post(
                _pix(
                    identity,
                    amount=10000,
                    transaction_date=f"2026-10-17T10:{minute:02d}:00-03:00",
                )
            )

        response = _post(
            _pix(identity, amount=10000, transaction_date="2026-10-17T10:04:00-03:00")
        )

        assert "VELOCITY_COUNT" in response["metadata"]["triggered_rules"]

    def test_dest_many_payers_fires(self):
        dest = RandomGenerator.generate_cpf()
        dest_account = {
            "opening_date": "2020-10-10T09:00:00-03:00",
            "owner": {"document_number": dest},
        }
        for _ in range(4):
            _post(
                _pix(
                    {**_identity(), "dest_document": dest},
                    transaction_date="2026-10-17T10:00:00-03:00",
                    destination_account=dest_account,
                )
            )

        response = _post(
            _pix(
                {**_identity(), "dest_document": dest},
                transaction_date="2026-10-17T11:00:00-03:00",
                destination_account=dest_account,
            )
        )

        assert "DEST_MANY_PAYERS" in response["metadata"]["triggered_rules"]

    def test_dest_inflow_spike_fires_without_many_payers(self):
        """10 inbound do mesmo pagador: spike sim, many-payers nao."""
        dest = RandomGenerator.generate_cpf()
        payer = _identity()
        dest_account = {
            "opening_date": "2020-10-10T09:00:00-03:00",
            "owner": {"document_number": dest},
        }
        for minute in range(9):
            _post(
                _pix(
                    {**payer, "dest_document": dest},
                    amount=10000,
                    transaction_date=f"2026-10-17T10:{minute:02d}:00-03:00",
                    destination_account=dest_account,
                )
            )

        response = _post(
            _pix(
                {**payer, "dest_document": dest},
                amount=10000,
                transaction_date="2026-10-17T10:09:00-03:00",
                destination_account=dest_account,
            )
        )

        assert "DEST_INFLOW_SPIKE" in response["metadata"]["triggered_rules"]
        assert "DEST_MANY_PAYERS" not in response["metadata"]["triggered_rules"]

    def test_new_dest_concentration_fires(self):
        identity = _identity()
        for day in range(10, 13):
            _post(
                _pix(
                    identity,
                    amount=20000,
                    transaction_date=f"2026-10-{day}T14:00:00-03:00",
                )
            )

        response = _post(
            _pix(
                {**identity, "dest_document": RandomGenerator.generate_cpf()},
                amount=100000,
                transaction_date="2026-10-17T14:00:00-03:00",
            )
        )

        assert "NEW_DEST_CONCENTRATION" in response["metadata"]["triggered_rules"]
        assert "UNKNOWN_DEST" in response["metadata"]["triggered_rules"]

    def test_channel_anomaly_fires(self):
        identity = _identity()
        for day in range(10, 13):
            _post(
                _pix(identity, amount=10000, transaction_date=f"2026-10-{day}T14:00:00-03:00")
            )

        response = _post(
            _pix(
                identity,
                amount=10000,
                transaction_date="2026-10-17T14:00:00-03:00",
                source={
                    "device_id": identity["device_id"],
                    "channel": "web",
                    "ip": identity["ip"],
                    "geolocation": {"latitude": -23.56, "longitude": -46.65},
                },
            )
        )

        assert "CHANNEL_ANOMALY" in response["metadata"]["triggered_rules"]

    def test_dest_prior_rejects_and_unknown_dest_pattern(self):
        dest = RandomGenerator.generate_cpf()
        new_dest_account = {
            "opening_date": "2026-10-15T09:00:00-03:00",
            "owner": {"document_number": dest},
        }
        for _ in range(3):
            rejected = _post(
                _pix(
                    {**_identity(), "dest_document": dest},
                    amount=6_000_000,
                    transaction_date="2026-10-16T10:00:00-03:00",
                    destination_account=new_dest_account,
                )
            )
            assert rejected["status"] == "rejected"

        response = _post(
            _pix(
                {**_identity(), "dest_document": dest},
                amount=15000,
                transaction_date="2026-10-17T10:00:00-03:00",
                destination_account=new_dest_account,
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "PRIOR_REJECTS_AND_UNKNOWN_DEST"
        assert "DEST_PRIOR_REJECTS" in response["metadata"]["triggered_rules"]
        assert "UNKNOWN_DEST" in response["metadata"]["triggered_rules"]

    def test_new_dest_account_fires(self):
        response = _post(
            _pix(
                _identity(),
                transaction_date="2026-10-17T14:00:00-03:00",
                destination_account={
                    "opening_date": "2026-10-15T09:00:00-03:00",
                    "owner": {"document_number": RandomGenerator.generate_cpf()},
                },
            )
        )

        assert "NEW_DEST_ACCOUNT" in response["metadata"]["triggered_rules"]

    def test_new_source_account_fires(self):
        identity = _identity()
        response = _post(
            _pix(
                identity,
                transaction_date="2026-10-17T14:00:00-03:00",
                source_account={
                    "opening_date": "2026-09-20T10:00:00-03:00",
                    "owner": {"document_number": identity["source_document"]},
                },
            )
        )

        assert "NEW_SOURCE_ACCOUNT" in response["metadata"]["triggered_rules"]

    def test_payer_many_accounts_fires(self):
        identity = _identity()
        for minute in range(4):
            _post(
                _pix(
                    {**identity, "dest_document": RandomGenerator.generate_cpf()},
                    amount=10000,
                    transaction_date=f"2026-10-17T10:{minute:02d}:00-03:00",
                )
            )

        response = _post(
            _pix(
                {**identity, "dest_document": RandomGenerator.generate_cpf()},
                amount=10000,
                transaction_date="2026-10-17T10:05:00-03:00",
            )
        )

        assert "PAYER_MANY_ACCOUNTS" in response["metadata"]["triggered_rules"]

    def test_shared_device_fires_for_third_payer(self):
        shared_device = f"dvc-{uuid4().hex[:8]}"
        for _ in range(2):
            _post(
                _pix(
                    {**_identity(), "device_id": shared_device},
                    transaction_date="2026-10-17T10:00:00-03:00",
                )
            )

        response = _post(
            _pix(
                {**_identity(), "device_id": shared_device},
                transaction_date="2026-10-17T11:00:00-03:00",
            )
        )

        assert "SHARED_DEVICE" in response["metadata"]["triggered_rules"]

    def test_out_of_profile_and_new_dest_pattern_rejects(self):
        identity = _identity()
        _prime_profile(identity)
        new_dest = RandomGenerator.generate_cpf()

        response = _post(
            _pix(
                {**identity, "dest_document": new_dest},
                amount=500000,
                transaction_date="2026-10-17T14:00:00-03:00",
                destination_account={
                    "opening_date": "2026-10-15T09:00:00-03:00",
                    "owner": {"document_number": new_dest},
                },
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "OUT_OF_PROFILE_AND_NEW_DEST"
        assert "AMOUNT_OUT_OF_PROFILE" in response["metadata"]["triggered_rules"]
        assert "NEW_DEST_ACCOUNT" in response["metadata"]["triggered_rules"]
        assert "UNKNOWN_DEST" in response["metadata"]["triggered_rules"]

    def test_velocity_and_unknown_device_pattern_rejects(self):
        """Rajada no device conhecido + 5o Pix ja no device novo (ainda desconhecido)."""
        identity = _identity()
        for minute in range(4):
            _post(
                _pix(
                    identity,
                    amount=10000,
                    transaction_date=f"2026-10-17T10:{minute:02d}:00-03:00",
                )
            )

        response = _post(
            _pix(
                {**identity, "device_id": f"dvc-{uuid4().hex[:8]}"},
                amount=10000,
                transaction_date="2026-10-17T10:04:00-03:00",
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "VELOCITY_AND_UNKNOWN_DEVICE"
        assert "VELOCITY_COUNT" in response["metadata"]["triggered_rules"]
        assert "UNKNOWN_DEVICE" in response["metadata"]["triggered_rules"]

    def test_splitting_and_many_accounts_pattern_rejects(self):
        identity = _identity()
        for minute in range(4):
            _post(
                _pix(
                    {**identity, "dest_document": RandomGenerator.generate_cpf()},
                    amount=90000,
                    transaction_date=f"2026-10-17T10:{minute:02d}:00-03:00",
                )
            )

        response = _post(
            _pix(
                {**identity, "dest_document": RandomGenerator.generate_cpf()},
                amount=90000,
                transaction_date="2026-10-17T10:05:00-03:00",
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "SPLITTING_AND_MANY_ACCOUNTS"
        assert "AMOUNT_SPLITTING" in response["metadata"]["triggered_rules"]
        assert "PAYER_MANY_ACCOUNTS" in response["metadata"]["triggered_rules"]
        assert "UNKNOWN_DEST" in response["metadata"]["triggered_rules"]

    def test_inflow_spike_and_many_payers_pattern_rejects(self):
        dest = RandomGenerator.generate_cpf()
        new_dest_account = {
            "opening_date": "2026-10-15T09:00:00-03:00",
            "owner": {"document_number": dest},
        }
        for index in range(9):
            _post(
                _pix(
                    {**_identity(), "dest_document": dest},
                    amount=10000,
                    transaction_date=f"2026-10-17T10:{index:02d}:00-03:00",
                    destination_account=new_dest_account,
                )
            )

        response = _post(
            _pix(
                {**_identity(), "dest_document": dest},
                amount=10000,
                transaction_date="2026-10-17T10:09:00-03:00",
                destination_account=new_dest_account,
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "INFLOW_SPIKE_AND_MANY_PAYERS"
        assert "DEST_INFLOW_SPIKE" in response["metadata"]["triggered_rules"]
        assert "DEST_MANY_PAYERS" in response["metadata"]["triggered_rules"]
        assert "NEW_DEST_ACCOUNT" in response["metadata"]["triggered_rules"]

    def test_shared_device_and_velocity_pattern_rejects(self):
        shared_device = f"dvc-{uuid4().hex[:8]}"
        for _ in range(2):
            _post(
                _pix(
                    {**_identity(), "device_id": shared_device},
                    transaction_date="2026-10-17T09:00:00-03:00",
                )
            )

        identity = {**_identity(), "device_id": shared_device}
        for minute in range(4):
            _post(
                _pix(
                    identity,
                    amount=10000,
                    transaction_date=f"2026-10-17T10:{minute:02d}:00-03:00",
                )
            )

        response = _post(
            _pix(
                {**identity, "dest_document": RandomGenerator.generate_cpf()},
                amount=10000,
                transaction_date="2026-10-17T10:04:00-03:00",
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "SHARED_DEVICE_AND_VELOCITY"
        assert "SHARED_DEVICE" in response["metadata"]["triggered_rules"]
        assert "VELOCITY_COUNT" in response["metadata"]["triggered_rules"]
        assert "UNKNOWN_DEST" in response["metadata"]["triggered_rules"]

    def test_geo_and_unknown_device_pattern_rejects(self):
        identity = _identity()
        _post(
            _pix(
                identity,
                transaction_date="2026-10-17T10:00:00-03:00",
                source={
                    "device_id": identity["device_id"],
                    "channel": "app",
                    "ip": identity["ip"],
                    "geolocation": {"latitude": -23.56, "longitude": -46.65},
                },
            )
        )

        new_device = f"dvc-{uuid4().hex[:8]}"
        response = _post(
            _pix(
                {**identity, "device_id": new_device},
                transaction_date="2026-10-17T10:30:00-03:00",
                source={
                    "device_id": new_device,
                    "channel": "app",
                    "ip": identity["ip"],
                    "geolocation": {"latitude": -8.05, "longitude": -34.88},
                },
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "GEO_AND_UNKNOWN_DEVICE"
        assert "IMPLAUSIBLE_GEO" in response["metadata"]["triggered_rules"]
        assert "UNKNOWN_DEVICE" in response["metadata"]["triggered_rules"]

    def test_ceiling_and_unknown_device_pattern_rejects(self):
        identity = _identity()
        _post(_pix(identity, amount=10000, transaction_date="2026-10-17T10:00:00-03:00"))
        new_dest = RandomGenerator.generate_cpf()

        response = _post(
            _pix(
                {
                    **identity,
                    "device_id": f"dvc-{uuid4().hex[:8]}",
                    "dest_document": new_dest,
                },
                amount=6_000_000,
                transaction_date="2026-10-17T11:00:00-03:00",
                destination_account={
                    "opening_date": "2020-10-10T09:00:00-03:00",
                    "owner": {"document_number": new_dest},
                },
            )
        )

        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "CEILING_AND_UNKNOWN_DEVICE"
        assert "AMOUNT_HARD_CEILING" in response["metadata"]["triggered_rules"]
        assert "UNKNOWN_DEVICE" in response["metadata"]["triggered_rules"]
        assert "UNKNOWN_DEST" in response["metadata"]["triggered_rules"]
        assert "NEW_DEST_ACCOUNT" not in response["metadata"]["triggered_rules"]
