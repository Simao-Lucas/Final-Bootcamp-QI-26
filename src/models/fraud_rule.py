from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from models.base import Base


class FraudRule(Base):
    __tablename__ = "fraud_rule"

    id = Column(Integer, primary_key=True)
    rule_set_id = Column(Integer, ForeignKey("fraud_rule_set.id"), nullable=False)
    code = Column(String(64), nullable=False)
    bit_index = Column(SmallInteger, nullable=False)
    weight = Column(Integer, nullable=False)
    params = Column(JSONB, nullable=False, default=dict)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("rule_set_id", "code"),
        UniqueConstraint("rule_set_id", "bit_index"),
        CheckConstraint("bit_index >= 0 AND bit_index <= 62"),
        CheckConstraint("weight >= 0"),
    )

    rule_set = relationship("FraudRuleSet", back_populates="rules")
