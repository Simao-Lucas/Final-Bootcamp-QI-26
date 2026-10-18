from database import Context
from models import FraudRuleSet


class FraudRuleSetRepository:
    def __init__(self, context: Context) -> None:
        self.session = context.db_session

    def get_active(self) -> FraudRuleSet:
        return (
            self.session.query(FraudRuleSet)
            .filter(FraudRuleSet.is_active.is_(True))
            .one()
        )
