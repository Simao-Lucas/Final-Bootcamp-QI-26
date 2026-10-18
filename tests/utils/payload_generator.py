from copy import deepcopy
from uuid import uuid4

from tests.utils.random_generator import RandomGenerator


class PayloadGenerator:
    @staticmethod
    def create_pix_transaction_payload(**overrides) -> dict:
        """Um Pix valido no formato do desafio, com campos trocaveis.

        Sem overrides sai um perfil "calmo": valor baixo, contas antigas,
        device/ip estaveis — candidato natural a `approved` quando o motor
        existir. Os testes de 2FA/reject passam overrides (valor alto,
        conta destino nova, etc.).
        """
        payload = {
            "id": f"pix-{uuid4()}",
            "amount": 15000,
            "transaction_date": "2026-10-17T14:15:00-03:00",
            "source_account": {
                "branch": "0001",
                "account_number": "88213",
                "opening_date": "2020-03-02T10:00:00-03:00",
                "owner": {"document_number": RandomGenerator.generate_cpf()},
            },
            "destination_account": {
                "participant": "60701190",
                "branch": "3675",
                "account_number": "10442",
                "opening_date": "2020-10-10T09:00:00-03:00",
                "owner": {"document_number": RandomGenerator.generate_cpf()},
            },
            "source": {
                "device_id": f"dvc-{uuid4().hex[:8]}",
                "channel": "app",
                "ip": "198.51.100.23",
                "geolocation": {"latitude": -23.56, "longitude": -46.65},
            },
        }

        for key, value in overrides.items():
            if (
                key in payload
                and isinstance(payload[key], dict)
                and isinstance(value, dict)
            ):
                merged = deepcopy(payload[key])
                for nested_key, nested_value in value.items():
                    if (
                        nested_key in merged
                        and isinstance(merged[nested_key], dict)
                        and isinstance(nested_value, dict)
                    ):
                        merged[nested_key] = {**merged[nested_key], **nested_value}
                    else:
                        merged[nested_key] = nested_value
                payload[key] = merged
            else:
                payload[key] = value

        return payload

    @staticmethod
    def create_sample_entity_payload(
        hello: str = None,
        name: str = None,
        email: str = None,
        document_number: str = None,
        birthdate: str = None,
    ) -> dict:
        """Um cadastro valido, com qualquer campo trocado a pedido.

        Sem argumento nenhum o payload sai aleatorio no que precisa ser
        unico (e-mail e CPF), pra que dois cadastros seguidos nao batam
        na regra de duplicidade. Quem testa FILTRO precisa do contrario
        disso: um valor conhecido, pra poder procurar por ele depois.
        """
        if hello is None:
            hello = "world"

        if name is None:
            name = "Maria da Silva"

        if email is None:
            email = f"maria.silva.{uuid4()}@exemplo.com.br"

        if document_number is None:
            document_number = RandomGenerator.generate_cpf()

        if birthdate is None:
            birthdate = "1990-05-17"

        payload = {
            "hello": hello,
            "name": name,
            "email": email,
            "document_number": document_number,
            "birthdate": birthdate,
        }
        return payload

    @staticmethod
    def create_new_status_payload(new_status: str = None) -> dict:
        payload = {"status": new_status}
        return payload
