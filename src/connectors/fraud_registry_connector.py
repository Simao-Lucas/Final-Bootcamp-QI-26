from urllib.parse import quote

import requests

from connectors.rest_connector import RestConnector
from constants import (
    FRAUD_REGISTRY_API_INTERNAL_TOKEN,
    FRAUD_REGISTRY_API_TIMEOUT,
    FRAUD_REGISTRY_API_URL,
)


class FraudRegistryConnector(RestConnector):
    """Consulta a API mock de condenacoes de CPF/CNPJ."""

    def __init__(self) -> None:
        super().__init__(
            class_name=__name__,
            base_url=FRAUD_REGISTRY_API_URL,
            timeout=FRAUD_REGISTRY_API_TIMEOUT,
            internal_token=FRAUD_REGISTRY_API_INTERNAL_TOKEN,
        )

    def check_document(self, document_number: str) -> dict:
        """Devolve um resultado normalizado — nunca sobe excecao pro controller.

        Formato:
          {"ok": True, "condemned": bool, "payload": dict}
          {"ok": False, "error": "timeout"|"error"}
        """
        endpoint = f"/fraud/document/{quote(document_number, safe='')}"
        try:
            response = self.send(endpoint=endpoint, method="GET")
        except requests.Timeout:
            return {"ok": False, "error": "timeout"}
        except requests.RequestException:
            return {"ok": False, "error": "error"}

        if response.status != 200 or not isinstance(response.json, dict):
            return {"ok": False, "error": "error"}

        return {
            "ok": True,
            "condemned": bool(response.json.get("condemned")),
            "payload": response.json,
        }
