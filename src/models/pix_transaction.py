from sqlalchemy import (
    BigInteger,
    CHAR,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from models.base import Base


class PixTransaction(Base):
    __tablename__ = "pix_transaction"

    id = Column(Integer, primary_key=True)
    analysis_key = Column(CHAR(36), nullable=False)
    pix_id = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False)
    rule_set_id = Column(Integer, ForeignKey("fraud_rule_set.id"), nullable=False)
    triggered_mask = Column(BigInteger, nullable=False, default=0)
    score = Column(Integer, nullable=False, default=0)
    amount = Column(BigInteger, nullable=False)
    transaction_date = Column(DateTime, nullable=False)
    source_document = Column(String(18), nullable=False)
    source_branch = Column(String(16), nullable=False)
    source_account_number = Column(String(32), nullable=False)
    source_opening_date = Column(DateTime, nullable=False)
    dest_document = Column(String(18), nullable=False)
    dest_participant = Column(String(16), nullable=False)
    dest_branch = Column(String(16), nullable=False)
    dest_account_number = Column(String(32), nullable=False)
    dest_opening_date = Column(DateTime, nullable=False)
    device_id = Column(String(64), nullable=False)
    channel = Column(String(32), nullable=False)
    ip = Column(String(45), nullable=False)
    latitude = Column(Numeric(10, 7), nullable=True)
    longitude = Column(Numeric(10, 7), nullable=True)
    metadata_json = Column("metadata", JSONB, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("analysis_key"),
        UniqueConstraint("pix_id"),
        CheckConstraint("status IN ('approved', 'rejected', 'two_factor_required')"),
        CheckConstraint("amount >= 0"),
        CheckConstraint("score >= 0"),
    )

    rule_set = relationship("FraudRuleSet", lazy="selectin")
