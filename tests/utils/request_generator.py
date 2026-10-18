from os import environ

from tests.utils.requisition import ClientRequisition, BaseConnectorResponse


INTERNAL_TOKEN = environ.get("INTERNAL_TOKEN", "default_token")


class RequestGenerator:
    @staticmethod
    def POST_pix_transaction(pix_payload: dict, headers: dict = None) -> BaseConnectorResponse:
        request_headers = {"INTERNAL-TOKEN": INTERNAL_TOKEN}
        if headers is not None:
            request_headers.update(headers)

        response = ClientRequisition.send(
            "POST",
            "/pix/transaction",
            payload=pix_payload,
            headers=request_headers,
        )
        return response.response_status, response.response_json

    @staticmethod
    def GET_pix_transaction(pix_id: str) -> BaseConnectorResponse:
        response = ClientRequisition.send(
            "GET",
            f"/pix/transaction/{pix_id}",
            headers={"INTERNAL-TOKEN": INTERNAL_TOKEN},
        )
        return response.response_status, response.response_json
