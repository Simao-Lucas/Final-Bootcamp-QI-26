"""Motor antifraude: avalia regras, monta bitmask/score e decide o status."""

from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from math import asin, cos, log, radians, sin, sqrt
from statistics import median

from models import FraudCriticalPattern, FraudRule, FraudRuleSet
from repositories import PixTransactionRepository


APPROVED = "approved"
REJECTED = "rejected"
TWO_FACTOR = "two_factor_required"


def match_critical_pattern(
    triggered_mask: int, patterns: list[FraudCriticalPattern]
) -> FraudCriticalPattern | None:
    for pattern in sorted(patterns, key=lambda item: item.id or 0):
        pattern_mask = int(pattern.pattern_mask)
        if (triggered_mask & pattern_mask) == pattern_mask:
            return pattern
    return None


def decide_status(
    triggered_mask: int,
    score: int,
    patterns: list[FraudCriticalPattern],
    score_threshold_2fa: int,
    score_threshold_reject: int | None = None,
) -> tuple[str, str, FraudCriticalPattern | None]:
    matched = match_critical_pattern(triggered_mask, patterns)
    if matched is not None:
        return REJECTED, "critical_pattern_matched", matched
    if score_threshold_reject is not None and score >= score_threshold_reject:
        return REJECTED, "score_above_reject_threshold", None
    if score >= score_threshold_2fa:
        return TWO_FACTOR, "score_above_threshold", None
    return APPROVED, "approved", None


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
            rule_set.score_threshold_reject,
        )

        metadata = {
            "rule_set_version": rule_set.version,
            "triggered_mask": triggered_mask,
            "triggered_rules": triggered_rules,
            "score": score,
            "score_threshold_2fa": rule_set.score_threshold_2fa,
            "score_threshold_reject": rule_set.score_threshold_reject,
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
            "REPEAT_AFTER_REJECT": self._repeat_after_reject,
            "REPEAT_AFTER_2FA": self._repeat_after_2fa,
            "VELOCITY_SUM": self._velocity_sum,
            "SHARED_DEVICE": self._shared_device,
            "DEST_PRIOR_REJECTS": self._dest_prior_rejects,
            "UNKNOWN_IP": self._unknown_ip,
            "AMOUNT_HARD_CEILING": self._amount_hard_ceiling,
            "CHANNEL_ANOMALY": self._channel_anomaly,
            "PASS_THROUGH": self._pass_through,
            "COLD_START_HIGH_AMOUNT": self._cold_start_high_amount,
            "NIGHT_HIGH_AMOUNT": self._night_high_amount,
            "DORMANT_REACTIVATION": self._dormant_reactivation,
            "MISSING_GEOLOCATION": self._missing_geolocation,
            "SHARED_IP": self._shared_ip,
        }
        handler = handlers.get(rule.code)
        if handler is None:
            return False
        return handler(rule.params or {}, context)

    # Sinais de "conhecido", de perfil e somas de valor ignoram Pix rejected:
    # tentativa barrada nao ensina ao motor o device/IP/destino do fraudador
    # e nao moveu dinheiro. two_factor_required conta como conhecido; sem
    # isso, quem troca de celular ficaria preso em 2FA (UNKNOWN_DEVICE +
    # REPEAT_AFTER_2FA = 40 a cada Pix). Contagens de tentativa (velocity,
    # destinos distintos) usam todo o historico.

    def _unknown_dest(self, params: dict, context: dict) -> bool:
        prior = self.pix_repository.count_source_to_dest(
            context["source_document"],
            context["dest_document"],
            until=context["transaction_date"],
            statuses=[APPROVED, TWO_FACTOR],
        )
        return prior < int(params.get("min_prior_payments", 1))

    def _amount_out_of_profile(self, params: dict, context: dict) -> bool:
        if context["amount"] < int(params.get("min_amount_cents", 50000)):
            return False
        lookback = timedelta(days=int(params.get("lookback_days", 180)))
        history = [
            item
            for item in _since(
                _not_rejected(context["source_history"]),
                context["transaction_date"] - lookback,
            )
            if item.amount > 0
        ]
        segment = [
            item
            for item in history
            if _is_cnpj(item.dest_document) == context["dest_is_cnpj"]
        ]
        if len(segment) >= int(params.get("min_segment_history", 5)):
            profile = segment
        elif len(history) >= int(params.get("min_history", 5)):
            profile = history
        else:
            return False
        z_score = _robust_log_z_score(
            context["amount"],
            [item.amount for item in profile],
            float(params.get("min_log_spread", 0.4)),
        )
        return z_score >= float(params.get("z_threshold", 3))

    def _velocity_count(self, params: dict, context: dict) -> bool:
        window = timedelta(minutes=int(params.get("window_minutes", 10)))
        recent = _since(context["source_history"], context["transaction_date"] - window)
        # +1 for the current pix about to be stored
        return len(recent) + 1 >= int(params.get("max_count", 5))

    def _amount_splitting(self, params: dict, context: dict) -> bool:
        unit_ceiling = int(params.get("unit_ceiling_cents", 100000))
        if context["amount"] >= unit_ceiling:
            return False
        window = timedelta(minutes=int(params.get("window_minutes", 30)))
        recent = _since(
            _not_rejected(context["source_history"]),
            context["transaction_date"] - window,
        )
        parts = [item for item in recent if item.amount < unit_ceiling]
        current_sum = sum(item.amount for item in parts) + context["amount"]
        return (
            len(parts) + 1 >= int(params.get("min_parts", 3))
            and current_sum >= int(params.get("sum_ceiling_cents", 250000))
        )

    def _unknown_device(self, params: dict, context: dict) -> bool:
        history = _not_rejected(context["source_history"])
        if not history:
            return False
        return context["device_id"] not in {item.device_id for item in history}

    def _implausible_geo(self, params: dict, context: dict) -> bool:
        if context["latitude"] is None or context["longitude"] is None:
            return False
        history = [
            item
            for item in _not_rejected(context["source_history"])
            if item.latitude is not None and item.longitude is not None
        ]
        if not history:
            return False
        previous = history[-1]
        distance_km = _haversine_km(
            float(previous.latitude),
            float(previous.longitude),
            float(context["latitude"]),
            float(context["longitude"]),
        )
        if distance_km < float(params.get("min_distance_km", 100)):
            return False
        hours = (
            context["transaction_date"] - previous.transaction_date
        ).total_seconds() / 3600
        if hours <= 0:
            return True
        return distance_km / hours > float(params.get("max_km_per_hour", 1000))

    def _new_dest_account(self, params: dict, context: dict) -> bool:
        max_age_days = int(params.get("max_age_days", 7))
        age = context["transaction_date"] - context["dest_opening_date"]
        return age <= timedelta(days=max_age_days)

    def _dest_many_payers(self, params: dict, context: dict) -> bool:
        window = timedelta(hours=int(params.get("window_hours", 24)))
        inbound = _since(
            _not_rejected(context["dest_history"]),
            context["transaction_date"] - window,
        )
        payers = {item.source_document for item in inbound}
        payers.add(context["source_document"])
        limit = _by_document_type(
            params, "max_payers", 5, context["dest_is_cnpj"]
        )
        return len(payers) >= limit

    def _dest_inflow_spike(self, params: dict, context: dict) -> bool:
        window_hours = int(params.get("window_hours", 6))
        window_start = context["transaction_date"] - timedelta(hours=window_hours)
        inbound = _not_rejected(context["dest_history"])
        recent_count = len(_since(inbound, window_start)) + 1
        floor = _by_document_type(
            params, "max_inbound_count", 10, context["dest_is_cnpj"]
        )
        if recent_count < floor:
            return False
        baseline_days = int(params.get("baseline_days", 30))
        baseline_start = window_start - timedelta(days=baseline_days)
        baseline_count = sum(
            1
            for item in inbound
            if baseline_start <= item.transaction_date < window_start
        )
        expected = baseline_count * window_hours / (baseline_days * 24)
        return recent_count >= expected * float(params.get("spike_multiplier", 5))

    def _payer_many_accounts(self, params: dict, context: dict) -> bool:
        window = timedelta(minutes=int(params.get("window_minutes", 60)))
        recent = _since(context["source_history"], context["transaction_date"] - window)
        destinations = {item.dest_document for item in recent}
        destinations.add(context["dest_document"])
        limit = _by_document_type(
            params, "max_destinations", 5, context["source_is_cnpj"]
        )
        return len(destinations) >= limit

    def _new_source_account(self, params: dict, context: dict) -> bool:
        max_age_days = int(params.get("max_age_days", 30))
        age = context["transaction_date"] - context["source_opening_date"]
        return age <= timedelta(days=max_age_days)

    def _atypical_hour(self, params: dict, context: dict) -> bool:
        start = int(params.get("night_start_hour", 0))
        end = int(params.get("night_end_hour", 5))
        if not _hour_in_range(context["transaction_date"].hour, start, end):
            return False
        history = _not_rejected(context["source_history"])
        if len(history) < int(params.get("min_history", 10)):
            return True
        night_count = sum(
            1
            for item in history
            if _hour_in_range(item.transaction_date.hour, start, end)
        )
        return night_count / len(history) < float(params.get("habitual_share", 0.2))

    def _new_dest_concentration(self, params: dict, context: dict) -> bool:
        if not self._unknown_dest({"min_prior_payments": 1}, context):
            return False
        window = timedelta(days=int(params.get("window_days", 30)))
        recent = _since(
            _not_rejected(context["source_history"]),
            context["transaction_date"] - window,
        )
        if len(recent) < int(params.get("min_history", 3)):
            return False
        outflow = sum(item.amount for item in recent) + context["amount"]
        if outflow < int(params.get("min_outflow_cents", 100000)):
            return False
        share = context["amount"] / outflow
        return share >= float(params.get("min_share", 0.5))

    def _repeat_after_reject(self, params: dict, context: dict) -> bool:
        return self._repeat_after_status(params, context, [REJECTED])

    def _repeat_after_2fa(self, params: dict, context: dict) -> bool:
        return self._repeat_after_status(params, context, [TWO_FACTOR])

    def _repeat_after_status(
        self, params: dict, context: dict, statuses: list[str]
    ) -> bool:
        window = timedelta(minutes=int(params.get("window_minutes", 60)))
        return self.pix_repository.has_recent_status_for_source(
            context["source_document"],
            statuses,
            since=context["transaction_date"] - window,
            until=context["transaction_date"],
        )

    def _velocity_sum(self, params: dict, context: dict) -> bool:
        window = timedelta(minutes=int(params.get("window_minutes", 60)))
        recent = _since(
            _not_rejected(context["source_history"]),
            context["transaction_date"] - window,
        )
        # Pix isolado de valor alto e papel de AMOUNT_HARD_CEILING /
        # COLD_START_HIGH_AMOUNT; aqui so acumulacao.
        if not recent:
            return False
        total = sum(item.amount for item in recent) + context["amount"]
        ceiling = _by_document_type(
            params, "sum_ceiling_cents", 1000000, context["source_is_cnpj"]
        )
        lookback = timedelta(days=int(params.get("lookback_days", 90)))
        profile = _since(
            _not_rejected(context["source_history"]),
            context["transaction_date"] - lookback,
        )
        largest = max((item.amount for item in profile), default=0)
        ceiling = max(ceiling, largest * float(params.get("profile_multiplier", 2)))
        return total >= ceiling

    def _shared_device(self, params: dict, context: dict) -> bool:
        window = timedelta(days=int(params.get("window_days", 30)))
        others = self.pix_repository.count_other_payers_for_device(
            context["device_id"],
            context["source_document"],
            since=context["transaction_date"] - window,
            until=context["transaction_date"],
        )
        return others + 1 >= int(params.get("max_payer_documents", 3))

    def _dest_prior_rejects(self, params: dict, context: dict) -> bool:
        window = timedelta(days=int(params.get("window_days", 7)))
        payers = self.pix_repository.count_distinct_rejecting_payers_for_dest(
            context["dest_document"],
            since=context["transaction_date"] - window,
            until=context["transaction_date"],
        )
        limit = _by_document_type(
            params, "min_rejecting_payers", 3, context["dest_is_cnpj"]
        )
        return payers >= limit

    def _unknown_ip(self, params: dict, context: dict) -> bool:
        history = _not_rejected(context["source_history"])
        if not history:
            return False
        v4_prefix = int(params.get("ipv4_prefix", 24))
        v6_prefix = int(params.get("ipv6_prefix", 48))
        known = {_ip_block(item.ip, v4_prefix, v6_prefix) for item in history}
        return _ip_block(context["ip"], v4_prefix, v6_prefix) not in known

    def _amount_hard_ceiling(self, params: dict, context: dict) -> bool:
        ceiling = _by_document_type(
            params, "ceiling_cents", 5000000, context["source_is_cnpj"]
        )
        if context["amount"] < ceiling:
            return False
        lookback = timedelta(days=int(params.get("lookback_days", 180)))
        profile = _since(
            _not_rejected(context["source_history"]),
            context["transaction_date"] - lookback,
        )
        if len(profile) < int(params.get("min_history", 5)):
            return True
        largest = max(item.amount for item in profile)
        multiplier = float(params.get("profile_multiplier", 1.5))
        return context["amount"] >= largest * multiplier

    def _channel_anomaly(self, params: dict, context: dict) -> bool:
        history = _not_rejected(context["source_history"])
        if len(history) < int(params.get("min_history", 3)):
            return False
        return context["channel"] not in {item.channel for item in history}

    def _pass_through(self, params: dict, context: dict) -> bool:
        window = timedelta(minutes=int(params.get("window_minutes", 60)))
        since = context["transaction_date"] - window
        inbound = _not_rejected(
            self.pix_repository.list_by_dest_document(
                context["source_document"],
                since=since,
                until=context["transaction_date"],
            )
        )
        inbound_sum = sum(item.amount for item in inbound)
        if inbound_sum < int(params.get("min_inbound_cents", 100000)):
            return False
        outflow = sum(
            item.amount
            for item in _since(_not_rejected(context["source_history"]), since)
        ) + context["amount"]
        return outflow >= inbound_sum * float(params.get("min_ratio", 0.8))

    def _cold_start_high_amount(self, params: dict, context: dict) -> bool:
        history = _not_rejected(context["source_history"])
        if len(history) >= int(params.get("max_history", 5)):
            return False
        return context["amount"] >= int(params.get("min_amount_cents", 300000))

    def _night_high_amount(self, params: dict, context: dict) -> bool:
        if context["source_is_cnpj"]:
            return False
        start = int(params.get("night_start_hour", 20))
        end = int(params.get("night_end_hour", 6))
        if not _hour_in_range(context["transaction_date"].hour, start, end):
            return False
        return context["amount"] > int(params.get("amount_ceiling_cents", 100000))

    def _dormant_reactivation(self, params: dict, context: dict) -> bool:
        history = _not_rejected(context["source_history"])
        if not history:
            return False
        idle = context["transaction_date"] - history[-1].transaction_date
        return idle >= timedelta(days=int(params.get("inactive_days", 90)))

    def _missing_geolocation(self, params: dict, context: dict) -> bool:
        if context["latitude"] is not None and context["longitude"] is not None:
            return False
        history = _not_rejected(context["source_history"])
        if len(history) < int(params.get("min_history", 5)):
            return False
        with_geo = sum(
            1
            for item in history
            if item.latitude is not None and item.longitude is not None
        )
        return with_geo / len(history) >= float(params.get("min_geo_share", 0.8))

    def _shared_ip(self, params: dict, context: dict) -> bool:
        window = timedelta(hours=int(params.get("window_hours", 24)))
        others = self.pix_repository.count_other_payers_for_ip(
            context["ip"],
            context["source_document"],
            since=context["transaction_date"] - window,
            until=context["transaction_date"],
        )
        return others + 1 >= int(params.get("max_payer_documents", 6))


def _not_rejected(items: list) -> list:
    return [item for item in items if item.status != REJECTED]


def _since(items: list, since: datetime) -> list:
    return [item for item in items if item.transaction_date >= since]


def _hour_in_range(hour: int, start: int, end: int) -> bool:
    if start <= end:
        return start <= hour < end
    return hour >= start or hour < end


def _robust_log_z_score(amount: int, amounts: list[int], min_spread: float) -> float:
    # Valores de Pix sao assimetricos (muitos pequenos, poucos grandes): em log
    # a distribuicao fica proxima de simetrica. MAD * 1.4826 estima o desvio
    # padrao sem ser puxado por outliers; o piso evita que um perfil uniforme
    # (MAD = 0) dispare em qualquer variacao pequena.
    logs = [log(value) for value in amounts]
    center = median(logs)
    mad = median(abs(value - center) for value in logs)
    spread = max(1.4826 * mad, min_spread)
    return (log(amount) - center) / spread


def _is_cnpj(document_number: str) -> bool:
    return "/" in document_number


def _by_document_type(params: dict, key: str, default: int, is_cnpj: bool) -> int:
    value = params.get(key, default)
    if is_cnpj:
        value = params.get(f"{key}_cnpj", value)
    return int(value)


def _ip_block(ip: str, v4_prefix: int, v6_prefix: int) -> str:
    try:
        address = ip_address(ip)
    except ValueError:
        return ip
    prefix = v4_prefix if address.version == 4 else v6_prefix
    return str(ip_network(f"{address}/{prefix}", strict=False))


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
    source_document = payload["source_account"]["owner"]["document_number"]
    dest_document = payload["destination_account"]["owner"]["document_number"]
    return {
        "amount": payload["amount"],
        "transaction_date": transaction_date,
        "source_document": source_document,
        "dest_document": dest_document,
        "source_is_cnpj": _is_cnpj(source_document),
        "dest_is_cnpj": _is_cnpj(dest_document),
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
