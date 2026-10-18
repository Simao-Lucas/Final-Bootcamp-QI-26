from models import PixTransaction


class PixTransactionDTO:
    @staticmethod
    def analysis_response(pix: PixTransaction) -> dict:
        return {
            "key": pix.analysis_key,
            "status": pix.status,
            "metadata": pix.metadata_json or {},
        }
