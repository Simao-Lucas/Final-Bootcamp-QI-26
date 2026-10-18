"""Motor antifraude: avalia regras, monta bitmask/score e decide o status."""

from __future__ import annotations

from datetime import datetime, timedelta
from math import asin, cos, radians, sin, sqrt
from statistics import median

from models import FraudCriticalPattern, FraudRule, FraudRuleSet
from repositories import PixTransactionRepository


def match_critical_pattern(
    triggered_mask: int, patterns: list[FraudCriticalPattern]
) -> FraudCriticalPattern | None:
    for pattern in patterns:
        pattern_mask = int(pattern.pattern_mask)
        if (triggered_mask & pattern_mask) == pattern_mask:
            return pattern
    return None


def decide_status(
    triggered_mask: int,
    score: int,
    patterns: list[FraudCriticalPattern],
    score_threshold_2fa: int,
) -> tuple[str, str, FraudCriticalPattern | None]:
    matched = match_critical_pattern(triggered_mask, patterns)
    if matched is not None:
        return "rejected", "critical_pattern_matched", matched
    if score >= score_threshold_2fa:
        return "two_factor_required", "score_above_threshold", None
    return "approved", "approved", None


class FraudEngine:
    def __init__(self, pix_repository: PixTransactionRepository) -> None:
        self.pix_repository = pix_repository

    def evaluate(self, rule_set: FraudRuleSet, context: dict) -> dict:
        triggered_mask = 0
        score = 0
        triggered_rules: list[str] = []

        for rule in sorted(rule_set.rules, key=lambda item: item.bit_index):
            if self._rule_fires(rule, context):
                triggered_mask |= 1 << rule.bit_index
                score += rule.weight
                triggered_rules.append(rule.code)

        status, decision_reason, matched = decide_status(
            triggered_mask,
            score,
            list(rule_set.patterns),
            rule_set.score_threshold_2fa,
        )

        metadata = {
            "rule_set_version": rule_set.version,
            "triggered_mask": triggered_mask,
            "triggered_rules": triggered_rules,
            "score": score,
            "score_threshold_2fa": rule_set.score_threshold_2fa,
            "decision_reason": decision_reason,
            "matched_pattern": matched.code if matched is not None else None,
        }
        return {
            "status": status,
            "triggered_mask": triggered_mask,
            "score": score,
            "metadata": metadata,
        }

    def _rule_fires(self, rule: FraudRule, context: dict) -> bool:
        handlers = {
            "UNKNOWN_DEST": self._unknown_dest,
            "AMOUNT_OUT_OF_PROFILE": self._amount_out_of_profile,
            "VELOCITY_COUNT": self._velocity_count,
            "AMOUNT_SPLITTING": self._amount_splitting,
            "UNKNOWN_DEVICE": self._unknown_device,
            "IMPLAUSIBLE_GEO": self._implausible_geo,
            "NEW_DEST_ACCOUNT": self._new_dest_account,
            "DEST_MANY_PAYERS": self._dest_many_payers,
            "DEST_INFLOW_SPIKE": self._dest_inflow_spike,
            "PAYER_MANY_ACCOUNTS": self._payer_many_accounts,
            "NEW_SOURCE_ACCOUNT": self._new_source_account,
            "ATYPICAL_HOUR": self._atypical_hour,
            "NEW_DEST_CONCENTRATION": self._new_dest_concentration,
            "REPEAT_AFTER_ADVERSE": self._repeat_after_adverse,
            "VELOCITY_SUM": self._velocity_sum,
            "SHARED_DEVICE": self._shared_device,
            "DEST_PRIOR_REJECTS": self._dest_prior_rejects,
            "UNKNOWN_IP": self._unknown_ip,
            "AMOUNT_HARD_CEILING": self._amount_hard_ceiling,
            "CHANNEL_ANOMALY": self._channel_anomaly,
        }
        handler = handlers.get(rule.code)
        if handler is None:
            return False
        return handler(rule.params or {}, context)

    def _unknown_dest(self, params: dict, context: dict) -> bool:
        prior = self.pix_repository.count_source_to_dest(
            context["source_document"], context["dest_document"]
        )
        return prior < int(params.get("min_prior_payments", 1))

    def _amount_out_of_profile(self, params: dict, context: dict) -> bool:
        history = context["source_history"]
        min_history = int(params.get("min_history", 5))
        if len(history) < min_history:
            return False
        amounts = [item.amount for item in history]
        baseline = median(amounts)
        multiplier = float(params.get("profile_multiplier", 3))
        return context["amount"] >= baseline * multiplier

    def _velocity_count(self, params: dict, context: dict) -> bool:
        window = timedelta(minutes=int(params.get("window_minutes", 10)))
        since = context["transaction_date"] - window
        recent = [
            item
            for item in context["source_history"]
            if item.transaction_date >= since
        ]
        # +1 for the current pix about to be stored
        return len(recent) + 1 >= int(params.get("max_count", 5))

    def _amount_splitting(self, params: dict, context: dict) -> bool:
        window = timedelta(minutes=int(params.get("window_minutes", 30)))
        since = context["transaction_date"] - window
        unit_ceiling = int(params.get("unit_ceiling_cents", 100000))
        min_parts = int(params.get("min_parts", 3))
        sum_ceiling = int(params.get("sum_ceiling_cents", 500000))

        parts = [
            item
            for item in context["source_history"]
            if item.transaction_date >= since and item.amount < unit_ceiling
        ]
        if context["amount"] < unit_ceiling:
            current_sum = sum(item.amount for item in parts) + context["amount"]
            return len(parts) + 1 >= min_parts and current_sum >= sum_ceiling
        return False

    def _unknown_device(self, params: dict, context: dict) -> bool:
        history = context["source_history"]
        if not history:
            return False
        known_devices = {item.device_id for item in history}
        return context["device_id"] not in known_devices

    def _implausible_geo(self, params: dict, context: dict) -> bool:
        if context["latitude"] is None or context["longitude"] is None:
            return False
        history = [
            item
            for item in context["source_history"]
            if item.latitude is not None and item.longitude is not None
        ]
        if not history:
            return False
        previous = history[-1]
        hours = (
            context["transaction_date"] - previous.transaction_date
        ).total_seconds() / 3600
        if hours <= 0:
            return False
        distance_km = _haversine_km(
            float(previous.latitude),
            float(previous.longitude),
            float(context["latitude"]),
            float(context["longitude"]),
        )
        max_km_per_hour = float(params.get("max_km_per_hour", 800))
        return distance_km / hours > max_km_per_hour

    def _new_dest_account(self, params: dict, context: dict) -> bool:
        max_age_days = int(params.get("max_age_days", 7))
        age = context["transaction_date"] - context["dest_opening_date"]
        return age <= timedelta(days=max_age_days)

    def _dest_many_payers(self, params: dict, context: dict) -> bool:
        window = timedelta(hours=int(params.get("window_hours", 24)))
        since = context["transaction_date"] - window
        inbound = [
            item
            for item in context["dest_history"]
            if item.transaction_date >= since
        ]
        payers = {item.source_document for item in inbound}
        payers.add(context["source_document"])
        return len(payers) >= int(params.get("max_payers", 5))

    def _dest_inflow_spike(self, params: dict, context: dict) -> bool:
        window = timedelta(hours=int(params.get("window_hours", 6)))
        since = context["transaction_date"] - window
        inbound = [
            item
            for item in context["dest_history"]
            if item.transaction_date >= since
        ]
        return len(inbound) + 1 >= int(params.get("max_inbound_count", 10))

    def _payer_many_accounts(self, params: dict, context: dict) -> bool:
        window = timedelta(minutes=int(params.get("window_minutes", 60)))
        since = context["transaction_date"] - window
        recent = [
            item
            for item in context["source_history"]
            if item.transaction_date >= since
        ]
        destinations = {item.dest_document for item in recent}
        destinations.add(context["dest_document"])
        return len(destinations) >= int(params.get("max_destinations", 5))

    def _new_source_account(self, params: dict, context: dict) -> bool:
        max_age_days = int(params.get("max_age_days", 30))
        age = context["transaction_date"] - context["source_opening_date"]
        return age <= timedelta(days=max_age_days)

    def _atypical_hour(self, params: dict, context: dict) -> bool:
        start = int(params.get("night_start_hour", 0))
        end = int(params.get("night_end_hour", 5))
        hour = context["transaction_date"].hour
        if start <= end:
            return start <= hour < end
        return hour >= start or hour < end

    def _new_dest_concentration(self, params: dict, context: dict) -> bool:
        if not self._unknown_dest({"min_prior_payments": 1}, context):
            return False
        window = timedelta(hours=int(params.get("window_hours", 24)))
        since = context["transaction_date"] - window
        recent = [
            item
            for item in context["source_history"]
            if item.transaction_date >= since
        ]
        outflow = sum(item.amount for item in recent) + context["amount"]
        min_outflow = int(params.get("min_outflow_cents", 100000))
        if outflow < min_outflow:
            return False
        share = context["amount"] / outflow
        return share >= float(params.get("min_share", 0.7))

    def _repeat_after_adverse(self, params: dict, context: dict) -> bool:
        window = timedelta(minutes=int(params.get("window_minutes", 60)))
        since = context["transaction_date"] - window
        return self.pix_repository.has_recent_adverse_for_source(
            context["source_document"], since
        )

    def _velocity_sum(self, params: dict, context: dict) -> bool:
        window = timedelta(minutes=int(params.get("window_minutes", 60)))
        since = context["transaction_date"] - window
        recent = [
            item
            for item in context["source_history"]
            if item.transaction_date >= since
        ]
        total = sum(item.amount for item in recent) + context["amount"]
        return total >= int(params.get("sum_ceiling_cents", 1000000))

    def _shared_device(self, params: dict, context: dict) -> bool:
        window = timedelta(days=int(params.get("window_days", 30)))
        since = context["transaction_date"] - window
        distinct = self.pix_repository.count_distinct_devices_for_device(
            context["device_id"], since
        )
        # current payer may not be in history yet
        return distinct + 1 >= int(params.get("max_payer_documents", 2))

    def _dest_prior_rejects(self, params: dict, context: dict) -> bool:
        window = timedelta(days=int(params.get("window_days", 7)))
        since = context["transaction_date"] - window
        rejects = self.pix_repository.count_rejects_for_dest(
            context["dest_document"], since
        )
        return rejects >= int(params.get("min_rejects", 3))

    def _unknown_ip(self, params: dict, context: dict) -> bool:
        history = context["source_history"]
        if not history:
            return False
        known_ips = {item.ip for item in history}
        return context["ip"] not in known_ips

    def _amount_hard_ceiling(self, params: dict, context: dict) -> bool:
        return context["amount"] >= int(params.get("ceiling_cents", 5000000))

    def _channel_anomaly(self, params: dict, context: dict) -> bool:
        history = context["source_history"]
        min_history = int(params.get("min_history", 3))
        if len(history) < min_history:
            return False
        known_channels = {item.channel for item in history}
        return context["channel"] not in known_channels


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius_km = 6371.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = (
        sin(dlat / 2) ** 2
        + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    )
    return 2 * radius_km * asin(sqrt(a))


def build_evaluation_context(
    payload: dict,
    transaction_date: datetime,
    source_opening_date: datetime,
    dest_opening_date: datetime,
    source_history: list,
    dest_history: list,
) -> dict:
    source = payload["source"]
    geolocation = source.get("geolocation") or {}
    return {
        "amount": payload["amount"],
        "transaction_date": transaction_date,
        "source_document": payload["source_account"]["owner"]["document_number"],
        "dest_document": payload["destination_account"]["owner"]["document_number"],
        "source_opening_date": source_opening_date,
        "dest_opening_date": dest_opening_date,
        "device_id": source["device_id"],
        "channel": source["channel"],
        "ip": source["ip"],
        "latitude": geolocation.get("latitude"),
        "longitude": geolocation.get("longitude"),
        "source_history": source_history,
        "dest_history": dest_history,
    }
