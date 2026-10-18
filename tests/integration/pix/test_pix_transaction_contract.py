"""Contrato HTTP do Pix — suite TDD red (tests-pix-contract).

Cobre o que o desafio exige na borda da API: POST/GET, formato da
resposta, schema invalido, os tres status possiveis e idempotencia do
`id`. A matematica fina de bitmask/pattern fica na suite do motor.
"""

from uuid import uuid4

from tests.utils import PayloadGenerator, RequestGenerator
from tests.utils.requisition import ClientRequisition


ALLOWED_STATUSES = {"approved", "rejected", "two_factor_required"}


class TestPixTransactionContract:
    def test_refuses_empty_body(self):
        status, response = RequestGenerator.POST_pix_transaction({})
        assert status == 400
        assert response["code"] == "QIT000001"

    def test_refuses_unknown_field(self):
        payload = PayloadGenerator.create_pix_transaction_payload()
        payload["campo_que_nao_existe"] = 1

        status, response = RequestGenerator.POST_pix_transaction(payload)
        assert status == 400
        assert response["code"] == "QIT000001"

    def test_refuses_without_internal_token(self):
        payload = PayloadGenerator.create_pix_transaction_payload()
        response = ClientRequisition.send(
            "POST",
            "/pix/transaction",
            payload=payload,
            headers={},
        )

        assert response.response_status == 403
        assert response.response_json["code"] == "QIT000002"

    def test_post_returns_key_status_and_metadata(self):
        payload = PayloadGenerator.create_pix_transaction_payload()

        status, response = RequestGenerator.POST_pix_transaction(payload)
        assert status == 201
        assert "key" in response
        assert isinstance(response["key"], str)
        assert len(response["key"]) == 36
        assert response["status"] in ALLOWED_STATUSES
        assert isinstance(response["metadata"], dict)

    def test_get_returns_stored_analysis(self):
        payload = PayloadGenerator.create_pix_transaction_payload()

        post_status, post_response = RequestGenerator.POST_pix_transaction(payload)
        assert post_status == 201

        get_status, get_response = RequestGenerator.GET_pix_transaction(payload["id"])
        assert get_status == 200
        assert get_response["key"] == post_response["key"]
        assert get_response["status"] == post_response["status"]
        assert get_response["metadata"] == post_response["metadata"]

    def test_get_not_found(self):
        """404 de negocio (Pix inexistente), nao o sink generico de rota."""
        status, response = RequestGenerator.GET_pix_transaction(f"pix-inexistente-{uuid4()}")
        assert status == 404
        assert response["code"] == "QIT001008"

    def test_idempotent_post_same_pix_id(self):
        """O mesmo `id` nao gera segunda analise — devolve a ja gravada."""
        payload = PayloadGenerator.create_pix_transaction_payload()

        first_status, first_response = RequestGenerator.POST_pix_transaction(payload)
        assert first_status == 201

        second_status, second_response = RequestGenerator.POST_pix_transaction(payload)
        assert second_status == 201
        assert second_response["key"] == first_response["key"]
        assert second_response["status"] == first_response["status"]
        assert second_response["metadata"] == first_response["metadata"]

        get_status, get_response = RequestGenerator.GET_pix_transaction(payload["id"])
        assert get_status == 200
        assert get_response["key"] == first_response["key"]

    def test_approved_for_low_risk_pix(self):
        """Perfil calmo: valor baixo, contas antigas, horario comercial."""
        payload = PayloadGenerator.create_pix_transaction_payload(
            amount=15000,
            transaction_date="2026-10-17T14:15:00-03:00",
            source_account={
                "opening_date": "2020-03-02T10:00:00-03:00",
            },
            destination_account={
                "opening_date": "2020-10-10T09:00:00-03:00",
            },
        )

        status, response = RequestGenerator.POST_pix_transaction(payload)
        assert status == 201
        assert response["status"] == "approved"

    def test_two_factor_required_when_score_reaches_threshold(self):
        """Sinais que somam >= 40 sem casar pattern critico.

        Fora do perfil (30) + horario atipico (10) = 40, e nao ha
        pattern seed com bits 1+11.
        """
        payload = PayloadGenerator.create_pix_transaction_payload(
            amount=5_000_000,
            transaction_date="2026-10-17T02:15:00-03:00",
            destination_account={
                "opening_date": "2020-10-10T09:00:00-03:00",
            },
        )

        status, response = RequestGenerator.POST_pix_transaction(payload)
        assert status == 201
        assert response["status"] == "two_factor_required"
        assert response["metadata"]["score"] >= 40

    def test_rejected_when_critical_pattern_matches(self):
        """Teto absoluto + conta destino recente → pattern CEILING_AND_NEW_DEST."""
        payload = PayloadGenerator.create_pix_transaction_payload(
            amount=6_000_000,
            destination_account={
                "opening_date": "2026-10-15T09:00:00-03:00",
            },
        )

        status, response = RequestGenerator.POST_pix_transaction(payload)
        assert status == 201
        assert response["status"] == "rejected"
        assert response["metadata"]["matched_pattern"] == "CEILING_AND_NEW_DEST"
