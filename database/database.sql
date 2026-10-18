CREATE TABLE sample_entity_status(
    id		                        SERIAL PRIMARY KEY,
    enumerator                      VARCHAR(50) NOT NULL,
    created_at                      TIMESTAMP NOT NULL DEFAULT(NOW()),
    UNIQUE(enumerator)
);

INSERT INTO sample_entity_status (enumerator) VALUES
('created'),
('pending'),
('success'),
('failed');

CREATE TABLE sample_entity(
    id                              SERIAL PRIMARY KEY,
    sample_entity_key               CHAR(36) NOT NULL,
    status_id                       INTEGER NOT NULL REFERENCES sample_entity_status(id),
    sample_entity_data              JSONB NOT NULL,
    name                            VARCHAR(255) NOT NULL,
    email                           VARCHAR(255) NOT NULL,
    document_number                 CHAR(14) NOT NULL,
    birthdate                       DATE NOT NULL,
    counter                         INTEGER NOT NULL,
    created_at                      TIMESTAMP NOT NULL DEFAULT(NOW()),
    UNIQUE(sample_entity_key),
    UNIQUE(document_number),
    UNIQUE(email)
);

CREATE TABLE sample_entity_status_event(
    id                              SERIAL PRIMARY KEY,
    sample_entity_id                INTEGER NOT NULL REFERENCES sample_entity(id),
    status_id                       INTEGER NOT NULL REFERENCES sample_entity_status(id),
    event_datetime                  TIMESTAMP NOT NULL,
    created_at                      TIMESTAMP NOT NULL DEFAULT(NOW())
);

-- ---------------------------------------------------------------------------
-- Antifraude Pix
-- ---------------------------------------------------------------------------

CREATE TABLE fraud_rule_set(
    id                              SERIAL PRIMARY KEY,
    version                         INTEGER NOT NULL,
    score_threshold_2fa             INTEGER NOT NULL,
    score_threshold_reject          INTEGER,
    is_active                       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at                      TIMESTAMP NOT NULL DEFAULT(NOW()),
    UNIQUE(version),
    CHECK (score_threshold_reject IS NULL OR score_threshold_reject > score_threshold_2fa)
);

-- No máximo um rule_set ativo por vez
CREATE UNIQUE INDEX fraud_rule_set_one_active
    ON fraud_rule_set (is_active)
    WHERE is_active = TRUE;

CREATE TABLE fraud_rule(
    id                              SERIAL PRIMARY KEY,
    rule_set_id                     INTEGER NOT NULL REFERENCES fraud_rule_set(id),
    code                            VARCHAR(64) NOT NULL,
    bit_index                       SMALLINT NOT NULL,
    weight                          INTEGER NOT NULL,
    params                          JSONB NOT NULL DEFAULT '{}'::JSONB,
    description                     TEXT NOT NULL,
    created_at                      TIMESTAMP NOT NULL DEFAULT(NOW()),
    UNIQUE(rule_set_id, code),
    UNIQUE(rule_set_id, bit_index),
    CHECK (bit_index >= 0 AND bit_index <= 62),
    CHECK (weight >= 0)
);

CREATE TABLE fraud_critical_pattern(
    id                              SERIAL PRIMARY KEY,
    rule_set_id                     INTEGER NOT NULL REFERENCES fraud_rule_set(id),
    code                            VARCHAR(64) NOT NULL,
    pattern_mask                    BIGINT NOT NULL,
    description                     TEXT NOT NULL,
    created_at                      TIMESTAMP NOT NULL DEFAULT(NOW()),
    UNIQUE(rule_set_id, code),
    CHECK (pattern_mask <> 0)
);

CREATE TABLE pix_transaction(
    id                              SERIAL PRIMARY KEY,
    analysis_key                    CHAR(36) NOT NULL,
    pix_id                          VARCHAR(64) NOT NULL,
    status                          VARCHAR(32) NOT NULL,
    rule_set_id                     INTEGER NOT NULL REFERENCES fraud_rule_set(id),
    triggered_mask                  BIGINT NOT NULL DEFAULT 0,
    score                           INTEGER NOT NULL DEFAULT 0,
    amount                          BIGINT NOT NULL,
    transaction_date                TIMESTAMP NOT NULL,
    source_document                 VARCHAR(18) NOT NULL,
    source_branch                   VARCHAR(16) NOT NULL,
    source_account_number           VARCHAR(32) NOT NULL,
    source_opening_date             TIMESTAMP NOT NULL,
    dest_document                   VARCHAR(18) NOT NULL,
    dest_participant                VARCHAR(16) NOT NULL,
    dest_branch                     VARCHAR(16) NOT NULL,
    dest_account_number             VARCHAR(32) NOT NULL,
    dest_opening_date               TIMESTAMP NOT NULL,
    device_id                       VARCHAR(64) NOT NULL,
    channel                         VARCHAR(32) NOT NULL,
    ip                              VARCHAR(45) NOT NULL,
    latitude                        NUMERIC(10, 7),
    longitude                       NUMERIC(10, 7),
    metadata                        JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at                      TIMESTAMP NOT NULL DEFAULT(NOW()),
    UNIQUE(analysis_key),
    UNIQUE(pix_id),
    CHECK (status IN ('approved', 'rejected', 'two_factor_required')),
    CHECK (amount >= 0),
    CHECK (score >= 0)
);

CREATE INDEX pix_transaction_source_document_date_idx
    ON pix_transaction (source_document, transaction_date);

CREATE INDEX pix_transaction_dest_document_date_idx
    ON pix_transaction (dest_document, transaction_date);

CREATE TABLE document_watchlist(
    document_number                 VARCHAR(18) PRIMARY KEY,
    first_seen_at                   TIMESTAMP NOT NULL DEFAULT(NOW()),
    last_seen_at                    TIMESTAMP NOT NULL DEFAULT(NOW()),
    last_checked_at                 TIMESTAMP
);

CREATE INDEX document_watchlist_last_seen_at_idx
    ON document_watchlist (last_seen_at);

CREATE TABLE document_block(
    document_number                 VARCHAR(18) PRIMARY KEY,
    reason                          TEXT NOT NULL,
    source                          VARCHAR(64) NOT NULL,
    raw_payload                     JSONB NOT NULL DEFAULT '{}'::JSONB,
    blocked_at                      TIMESTAMP NOT NULL DEFAULT(NOW()),
    last_checked_at                 TIMESTAMP NOT NULL DEFAULT(NOW())
);

-- ---------------------------------------------------------------------------
-- Seed rule_set v1 — threshold 2FA = 40, reject por score = 150
-- pattern_mask = soma de (1 << bit_index) dos bits exigidos
-- Params *_cnpj substituem o limite padrão quando o documento é CNPJ.
-- ---------------------------------------------------------------------------

INSERT INTO fraud_rule_set (id, version, score_threshold_2fa, score_threshold_reject, is_active)
VALUES (1, 1, 40, 150, TRUE);

SELECT setval(pg_get_serial_sequence('fraud_rule_set', 'id'), 1);

INSERT INTO fraud_rule (rule_set_id, code, bit_index, weight, params, description) VALUES
(1, 'UNKNOWN_DEST',              0,  10, '{"min_prior_payments": 1}'::JSONB,
 'Pagador sem Pix não rejeitado anterior para este destino'),
(1, 'AMOUNT_OUT_OF_PROFILE',     1,  30, '{"z_threshold": 3, "min_log_spread": 0.4, "min_history": 5, "min_segment_history": 5, "min_amount_cents": 50000, "lookback_days": 180}'::JSONB,
 'Valor incomum: escore z robusto (mediana/MAD do log) >= 3 no perfil do tipo de destino (CPF/CNPJ), com fallback no perfil geral'),
(1, 'VELOCITY_COUNT',            2,  30, '{"max_count": 5, "window_minutes": 10}'::JSONB,
 'Muitas tentativas de Pix do mesmo pagador em pouco tempo'),
(1, 'AMOUNT_SPLITTING',          3,  30, '{"unit_ceiling_cents": 100000, "min_parts": 3, "window_minutes": 30, "sum_ceiling_cents": 250000}'::JSONB,
 'Vários Pix abaixo de um teto unitário somando alto na janela'),
(1, 'UNKNOWN_DEVICE',            4,  30, '{}'::JSONB,
 'device_id nunca visto em Pix não rejeitado deste pagador'),
(1, 'IMPLAUSIBLE_GEO',           5,  30, '{"max_km_per_hour": 1000, "min_distance_km": 100}'::JSONB,
 'Deslocamento acima da velocidade de um voo comercial desde o último Pix'),
(1, 'NEW_DEST_ACCOUNT',          6,  10, '{"max_age_days": 7}'::JSONB,
 'Conta destinatária aberta há pouco tempo'),
(1, 'DEST_MANY_PAYERS',          7,  30, '{"max_payers": 5, "max_payers_cnpj": 50, "window_hours": 24}'::JSONB,
 'Destinatário recebendo de muitos pagadores distintos'),
(1, 'DEST_INFLOW_SPIKE',         8,  30, '{"max_inbound_count": 10, "max_inbound_count_cnpj": 100, "window_hours": 6, "baseline_days": 30, "spike_multiplier": 5}'::JSONB,
 'Recebimentos na janela acima do piso e >= 5x a média histórica do destino'),
(1, 'PAYER_MANY_ACCOUNTS',       9,  30, '{"max_destinations": 5, "max_destinations_cnpj": 20, "window_minutes": 60}'::JSONB,
 'Pagador distribuindo para muitas contas distintas'),
(1, 'NEW_SOURCE_ACCOUNT',       10,  10, '{"max_age_days": 30}'::JSONB,
 'Conta pagadora recente'),
(1, 'ATYPICAL_HOUR',            11,  10, '{"night_start_hour": 0, "night_end_hour": 5, "min_history": 10, "habitual_share": 0.2}'::JSONB,
 'Madrugada, exceto para quem já faz ao menos 1 em cada 5 Pix nesse horário'),
(1, 'NEW_DEST_CONCENTRATION',   12,  20, '{"min_share": 0.5, "window_days": 30, "min_history": 3, "min_outflow_cents": 100000}'::JSONB,
 'Destino novo recebendo metade ou mais do outflow de 30 dias do pagador'),
(1, 'REPEAT_AFTER_REJECT',      13,  30, '{"window_minutes": 60}'::JSONB,
 'Nova tentativa após rejected recente'),
(1, 'VELOCITY_SUM',             14,  30, '{"sum_ceiling_cents": 1000000, "sum_ceiling_cents_cnpj": 10000000, "window_minutes": 60, "profile_multiplier": 2, "lookback_days": 90}'::JSONB,
 'Soma acumulada na janela acima do teto (ou de 2x o maior Pix do perfil)'),
(1, 'SHARED_DEVICE',            15,  30, '{"max_payer_documents": 3, "window_days": 30}'::JSONB,
 'Mesmo device_id usado por 3+ documentos pagadores'),
(1, 'DEST_PRIOR_REJECTS',       16,  30, '{"min_rejecting_payers": 3, "min_rejecting_payers_cnpj": 10, "window_days": 7}'::JSONB,
 'Destino com rejeições do motor vindas de vários pagadores distintos'),
(1, 'UNKNOWN_IP',               17,  10, '{"ipv4_prefix": 24, "ipv6_prefix": 48}'::JSONB,
 'Faixa de IP (/24 ou /48) nunca vista em Pix não rejeitado deste pagador'),
(1, 'AMOUNT_HARD_CEILING',      18,  20, '{"ceiling_cents": 5000000, "ceiling_cents_cnpj": 50000000, "min_history": 5, "lookback_days": 180, "profile_multiplier": 1.5}'::JSONB,
 'Agravante de AMOUNT_OUT_OF_PROFILE / COLD_START: valor sem precedente (>= 1,5x o maior Pix do perfil) e acima do piso (R$ 50 mil PF, R$ 500 mil PJ)'),
(1, 'CHANNEL_ANOMALY',          19,  10, '{"min_history": 3}'::JSONB,
 'Canal diferente do hábito do pagador'),
(1, 'PASS_THROUGH',             20,  30, '{"window_minutes": 60, "min_ratio": 0.8, "min_inbound_cents": 100000}'::JSONB,
 'Pagador repassando quase tudo (min_ratio) do que acabou de receber'),
(1, 'COLD_START_HIGH_AMOUNT',   21,  20, '{"max_history": 5, "min_amount_cents": 300000}'::JSONB,
 'Valor >= R$ 3.000 de pagador ainda sem perfil (menos de 5 Pix)'),
(1, 'NIGHT_HIGH_AMOUNT',        22,  20, '{"night_start_hour": 20, "night_end_hour": 6, "amount_ceiling_cents": 100000}'::JSONB,
 'Pessoa física acima de R$ 1.000 no período noturno'),
(1, 'DORMANT_REACTIVATION',     23,  20, '{"inactive_days": 90}'::JSONB,
 'Pagador sem Pix há 90+ dias'),
(1, 'MISSING_GEOLOCATION',      24,  15, '{"min_history": 5, "min_geo_share": 0.8}'::JSONB,
 'Geolocalização ausente para quem quase sempre envia'),
(1, 'SHARED_IP',                25,  20, '{"max_payer_documents": 6, "window_hours": 24}'::JSONB,
 'Mesmo IP usado por 6+ documentos pagadores'),
(1, 'REPEAT_AFTER_2FA',         26,  10, '{"window_minutes": 60}'::JSONB,
 'Nova tentativa após two_factor_required recente');

-- Pattern critico rejeita sem passar por 2FA: cada um combina um sinal de
-- comprometimento (device/IP/geo) ou de conta laranja com um destino novo,
-- para que cliente legitimo com um unico sinal forte caia em 2FA, nao em reject.
INSERT INTO fraud_critical_pattern (rule_set_id, code, pattern_mask, description) VALUES
(1, 'OUT_OF_PROFILE_AND_NEW_DEST',
 (1::BIGINT << 1) | (1::BIGINT << 6) | (1::BIGINT << 0),
 'Valor fora do perfil para conta destino recente, primeira vez'),
(1, 'VELOCITY_AND_UNKNOWN_DEVICE',
 (1::BIGINT << 2) | (1::BIGINT << 4),
 'Rajada de Pix + dispositivo desconhecido'),
(1, 'SPLITTING_AND_MANY_ACCOUNTS',
 (1::BIGINT << 3) | (1::BIGINT << 9) | (1::BIGINT << 0),
 'Fracionamento para muitos destinos, incluindo destino novo'),
(1, 'INFLOW_SPIKE_AND_MANY_PAYERS',
 (1::BIGINT << 8) | (1::BIGINT << 7) | (1::BIGINT << 6),
 'Explosão de inflow + muitos pagadores em conta destino recente'),
(1, 'CEILING_AND_NEW_DEST',
 (1::BIGINT << 18) | (1::BIGINT << 6) | (1::BIGINT << 0),
 'Teto absoluto para conta destino recente, primeira vez'),
(1, 'SHARED_DEVICE_AND_VELOCITY',
 (1::BIGINT << 15) | (1::BIGINT << 2) | (1::BIGINT << 0),
 'Device compartilhado + velocity para destino novo'),
(1, 'PRIOR_REJECTS_AND_UNKNOWN_DEST',
 (1::BIGINT << 16) | (1::BIGINT << 0),
 'Destino já rejeitado + primeira vez para este pagador'),
(1, 'GEO_AND_UNKNOWN_DEVICE',
 (1::BIGINT << 5) | (1::BIGINT << 4),
 'Geo improvável + dispositivo desconhecido'),
(1, 'ACCOUNT_TAKEOVER',
 (1::BIGINT << 4) | (1::BIGINT << 17) | (1::BIGINT << 1) | (1::BIGINT << 0),
 'Device e rede novos + valor fora do perfil + destino novo'),
(1, 'CEILING_AND_UNKNOWN_DEVICE',
 (1::BIGINT << 18) | (1::BIGINT << 4) | (1::BIGINT << 0),
 'Teto absoluto em device desconhecido para destino novo'),
(1, 'VELOCITY_SUM_AND_UNKNOWN_DEVICE',
 (1::BIGINT << 14) | (1::BIGINT << 4) | (1::BIGINT << 0),
 'Drenagem acumulada em device desconhecido para destino novo'),
(1, 'MULE_FORWARDING',
 (1::BIGINT << 10) | (1::BIGINT << 9) | (1::BIGINT << 3),
 'Conta pagadora nova fracionando para muitos destinos'),
(1, 'PASS_THROUGH_AND_NEW_SOURCE',
 (1::BIGINT << 20) | (1::BIGINT << 10),
 'Conta nova repassando o que acabou de receber'),
(1, 'DORMANT_AND_UNKNOWN_DEVICE',
 (1::BIGINT << 23) | (1::BIGINT << 4) | (1::BIGINT << 1),
 'Conta adormecida reativada em device novo com valor fora do perfil');
