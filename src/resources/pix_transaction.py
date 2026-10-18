from fastapi import status as http_status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from controllers.pix_transaction_controller import PixTransactionController
from utils.schema_handler import SchemaHandler


class PixTransactionResource:
    @SchemaHandler.validate("post_pix_transaction.json")
    def on_post(self, payload: dict) -> JSONResponse:
        controller = PixTransactionController()
        analysis = controller.analyze(payload)
        return JSONResponse(
            content=jsonable_encoder(analysis),
            status_code=http_status.HTTP_201_CREATED,
        )

    def on_get_by_id(self, id: str) -> JSONResponse:
        controller = PixTransactionController()
        analysis = controller.get_by_pix_id(id)
        return JSONResponse(
            content=jsonable_encoder(analysis),
            status_code=http_status.HTTP_200_OK,
        )
