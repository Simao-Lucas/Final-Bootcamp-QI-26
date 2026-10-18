from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import relationship

from models.base import Base


class FraudCriticalPattern(Base):
    __tablename__ = "fraud_critical_pattern"

    id = Column(Integer, primary_key=True)
    rule_set_id = Column(Integer, ForeignKey("fraud_rule_set.id"), nullable=False)
    code = Column(String(64), nullable=False)
    pattern_mask = Column(BigInteger, nullable=False)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("rule_set_id", "code"),
        CheckConstraint("pattern_mask <> 0"),
    )

    rule_set = relationship("FraudRuleSet", back_populates="patterns")
