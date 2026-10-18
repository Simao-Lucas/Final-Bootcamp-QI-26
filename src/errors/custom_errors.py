from errors import QIException


class NotFoundPixTransaction(QIException):
    code = "QIT001008"

    def __init__(self, pix_id) -> None:
        title = "Pix transaction not Found"
        http_status = 404
        description = f"Pix transaction with id {pix_id} was not found."
        translation = f"A análise do Pix {pix_id} não foi encontrada."
        super().__init__(title, self.code, http_status, description, translation)
