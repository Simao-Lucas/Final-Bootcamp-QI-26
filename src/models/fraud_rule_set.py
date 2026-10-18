from sqlalchemy import Boolean, Column, DateTime, Integer, UniqueConstraint, func
from sqlalchemy.orm import relationship

from models.base import Base


class FraudRuleSet(Base):
    __tablename__ = "fraud_rule_set"

    id = Column(Integer, primary_key=True)
    version = Column(Integer, nullable=False)
    score_threshold_2fa = Column(Integer, nullable=False)
    score_threshold_reject = Column(Integer, nullable=True)
    is_active = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    __table_args__ = (UniqueConstraint("version"),)

    rules = relationship("FraudRule", back_populates="rule_set", lazy="selectin")
    patterns = relationship("FraudCriticalPattern", back_populates="rule_set", lazy="selectin")
