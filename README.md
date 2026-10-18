# Antifraude Pix — Bootcamp QI Tech 2026

**Integrantes:** João Victor Pereira Avella, Lucas Toffolo Simão

---

## Como o motor de decisão funciona

Cada Pix passa por três camadas, nesta ordem:

1. **Denylist (freshness TTL)** — consulta `document_block` do pagador e do recebedor. Documentos **quentes** (vistos nas últimas `FRAUD_CHECK_TTL_HOURS`, padrão 6h) só leem o cache local; documentos **frios** consultam a API mock de condenações. Timeout da mock é **fail-open** (segue o motor). Job periódico só revalida documentos quentes.
2. **Regras versionadas** — o `fraud_rule_set` ativo (v1) avalia cada regra. Quem dispara liga o bit `1 << bit_index` e soma o **peso** ao score. O `triggered_mask` e o score ficam gravados na análise.
3. **Decisão** — patterns críticos e limiar de 2FA. Nenhuma regra rejeita sozinha.

Histórico relevante vem do próprio Postgres (`pix_transaction`). Sinais de “conhecido” (device, IP, destino, perfil de valor) **ignoram** Pix `rejected`, para tentativa barrada não treinar o motor. `two_factor_required` conta como conhecido (troca de celular legítima não fica presa em 2FA eterno).

```text
POST /pix/transaction
  → denylist?
  → regras → triggered_mask + score
  → pattern é submáscara do mask? → rejected
  → score >= 40? → two_factor_required
  → approved
GET /pix/transaction/{id} → análise gravada (idempotente no mesmo id)
```

---

## Regras

Rule set **v1**. Escala de pesos: contexto leve **10–15**, médio **20**, forte **30**, crítico sozinho para 2FA **40**. Limiar de 2FA: **40**. Reject **somente** por pattern crítico ou denylist — score alto sem pattern pede 2FA, nunca reject.

| Regra | Lógica | Parâmetros | Por quê |
|-------|--------|------------|---------|
| `UNKNOWN_DEST` (bit 0, w=10) | Pagador sem Pix aprovado/2FA prévio para este destino | `min_prior_payments: 1` | Destino novo é sinal fraco sozinho; vira crítico só em combinação |
| `AMOUNT_OUT_OF_PROFILE` (1, 30) | Z-score robusto (mediana/MAD do log) ≥ limiar no perfil do **tipo** de destino (CPF vs CNPJ), com fallback no perfil geral | `z_threshold: 3`, `min_log_spread: 0.4`, `min_history: 5`, `min_segment_history: 5`, `min_amount_cents: 50000`, `lookback_days: 180` | Pix é assimétrico; log + MAD evita falso positivo em quem já varia o valor. Segmento CPF/CNPJ evita confundir boleto PJ com Pix P2P |
| `VELOCITY_COUNT` (2, 30) | ≥ N tentativas do pagador na janela (conta rejected) | `max_count: 5`, `window_minutes: 10` | Rajada é sinal clássico de automação / drenagem |
| `AMOUNT_SPLITTING` (3, 40) | ≥ N partes abaixo do teto unitário somando alto | `unit_ceiling_cents: 100000`, `min_parts: 3`, `window_minutes: 30`, `sum_ceiling_cents: 250000` | Fracionamento para furar limite; peso 40 = 2FA sozinho |
| `UNKNOWN_DEVICE` (4, 30) | `device_id` nunca visto em Pix não rejeitado deste pagador | — | Comprometimento de conta / device farm; sozinho não rejeita |
| `IMPLAUSIBLE_GEO` (5, 40) | Deslocamento acima de velocidade de voo comercial desde o último Pix com geo | `max_km_per_hour: 1000`, `min_distance_km: 100` | Impossível fisicamente; peso 40. Piso de distância evita ruído GPS |
| `NEW_DEST_ACCOUNT` (6, 10) | Conta destino com idade ≤ N dias | `max_age_days: 7` | Conta laranja recente; leve porque abertura legítima existe |
| `DEST_MANY_PAYERS` (7, 30) | Muitos pagadores distintos → mesmo destino | `max_payers: 5`, `max_payers_cnpj: 50`, `window_hours: 24` | Mule CPF concentra; CNPJ (loja) tolera bem mais |
| `DEST_INFLOW_SPIKE` (8, 30) | Inbound na janela acima do piso e ≥ K× a média histórica | `max_inbound_count: 10` (+ `_cnpj: 100`), `window_hours: 6`, `baseline_days: 30`, `spike_multiplier: 5` | Pico relativo ao hábito do destino, não só contagem absoluta |
| `PAYER_MANY_ACCOUNTS` (9, 30) | Pagador → muitos destinos distintos | `max_destinations: 5` (+ `_cnpj: 20`), `window_minutes: 60` | Distribuição / smurfing |
| `NEW_SOURCE_ACCOUNT` (10, 10) | Conta pagadora recente | `max_age_days: 30` | Conta nova tem menos histórico; sinal de contexto |
| `ATYPICAL_HOUR` (11, 10) | Madrugada, exceto quem já opera nesse horário | `night_start_hour: 0`, `night_end_hour: 5`, `min_history: 10`, `habitual_share: 0.2` | Fuso Brasília; quem já faz 20%+ de madrugada não é penalizado |
| `NEW_DEST_CONCENTRATION` (12, 20) | Destino novo levando ≥ metade do outflow recente | `min_share: 0.5`, `window_days: 30`, `min_history: 3`, `min_outflow_cents: 100000` | “Esvaziamento” para contraparte nova |
| `REPEAT_AFTER_REJECT` (13, 30) | Nova tentativa após `rejected` recente | `window_minutes: 60` | Persistência após bloqueio |
| `VELOCITY_SUM` (14, 30) | Soma na janela ≥ teto (ou 2× o maior Pix do perfil); exige histórico na janela | `sum_ceiling_cents: 1e6` (+ `_cnpj: 1e7`), `window_minutes: 60`, `profile_multiplier: 2`, `lookback_days: 90` | Drenagem acumulada; Pix isolado alto é papel do teto/cold start |
| `SHARED_DEVICE` (15, 30) | Mesmo device em ≥ N documentos pagadores | `max_payer_documents: 3`, `window_days: 30` | Device farm; o próprio pagador não conta como “compartilhado” |
| `DEST_PRIOR_REJECTS` (16, 30) | Destino com rejects do motor de ≥ N pagadores distintos | `min_rejecting_payers: 3` (+ `_cnpj: 10`), `window_days: 7` | Destino já “queimado”; ignora reject só por denylist do pagador |
| `UNKNOWN_IP` (17, 10) | Prefixo de IP novo (/24 ou /48) | `ipv4_prefix: 24`, `ipv6_prefix: 48` | Troca de host na mesma rede não dispara; troca de faixa sim |
| `AMOUNT_HARD_CEILING` (18, 20) | Valor ≥ piso absoluto e sem precedente (≥ 1,5× o maior do perfil); cold start usa só o piso | `ceiling_cents: 5e6` (+ `_cnpj: 5e7`), `min_history: 5`, `lookback_days: 180`, `profile_multiplier: 1.5` | Agravante de valor absurdo; PF R$ 50 mil / PJ R$ 500 mil |
| `CHANNEL_ANOMALY` (19, 10) | Canal fora do hábito | `min_history: 3` | App→web/etc. sem histórico no canal |
| `PASS_THROUGH` (20, 30) | Outflow ≥ ratio do que acabou de receber | `window_minutes: 60`, `min_ratio: 0.8`, `min_inbound_cents: 100000` | Conta ponte / mule forwarding |
| `COLD_START_HIGH_AMOUNT` (21, 20) | Valor alto com &lt; N Pix de histórico | `max_history: 5`, `min_amount_cents: 300000` | Sem perfil ainda; R$ 3 mil+ merece fricção |
| `NIGHT_HIGH_AMOUNT` (22, 20) | PF acima do teto no período noturno (20h–6h) | `night_start_hour: 20`, `night_end_hour: 6`, `amount_ceiling_cents: 100000` | PJ opera à noite; PF alto à noite é suspeito |
| `DORMANT_REACTIVATION` (23, 20) | Sem Pix há ≥ N dias | `inactive_days: 90` | Conta adormecida reativada (takeover) |
| `MISSING_GEOLOCATION` (24, 15) | Geo ausente para quem quase sempre envia com geo | `min_history: 5`, `min_geo_share: 0.8` | Omissão súbita de localização |
| `SHARED_IP` (25, 20) | Mesmo IP em ≥ N pagadores | `max_payer_documents: 6`, `window_hours: 24` | Mais permissivo que device (NAT/CGNAT) |
| `REPEAT_AFTER_2FA` (26, 10) | Nova tentativa após `two_factor_required` | `window_minutes: 60` | Separado do reject: 2FA não deve empilhar com `UNKNOWN_DEVICE` e prender o cliente |

### Patterns críticos (reject)

Reject se `(triggered_mask & pattern_mask) == pattern_mask` (submáscara: bits a mais não salvam). Ideia: **compromisso** (device/IP/geo) ou **conta laranja** + destino/contexto novo — um sinal forte isolado cai em 2FA, não em reject.

| Pattern | Bits | Por quê |
|---------|------|---------|
| `OUT_OF_PROFILE_AND_NEW_DEST` | 1 + 6 + 0 | Valor atípico para conta destino recente, 1ª vez |
| `VELOCITY_AND_UNKNOWN_DEVICE` | 2 + 4 | Rajada em device novo |
| `SPLITTING_AND_MANY_ACCOUNTS` | 3 + 9 + 0 | Fracionamento para muitos destinos (incl. novo) |
| `INFLOW_SPIKE_AND_MANY_PAYERS` | 8 + 7 + 6 | Pico de inflow + muitos pagadores em conta nova |
| `CEILING_AND_NEW_DEST` | 18 + 6 + 0 | Teto absoluto para destino recente, 1ª vez |
| `SHARED_DEVICE_AND_VELOCITY` | 15 + 2 + 0 | Device farm + velocity para destino novo |
| `PRIOR_REJECTS_AND_UNKNOWN_DEST` | 16 + 0 | Destino já rejeitado + 1ª vez deste pagador |
| `GEO_AND_UNKNOWN_DEVICE` | 5 + 4 | Teletransporte + device novo |
| `ACCOUNT_TAKEOVER` | 4 + 17 + 1 + 0 | Device e rede novos + fora do perfil + destino novo |
| `CEILING_AND_UNKNOWN_DEVICE` | 18 + 4 + 0 | Teto em device novo para destino novo |
| `VELOCITY_SUM_AND_UNKNOWN_DEVICE` | 14 + 4 + 0 | Drenagem acumulada em device novo |
| `MULE_FORWARDING` | 10 + 9 + 3 | Conta pagadora nova fracionando para muitos destinos |
| `PASS_THROUGH_AND_NEW_SOURCE` | 20 + 10 | Conta nova repassando o que recebeu |
| `DORMANT_AND_UNKNOWN_DEVICE` | 23 + 4 + 1 | Conta adormecida + device novo + fora do perfil |

---

## Como as regras viram decisão

Ordem fixa no `POST /pix/transaction`:

1. **Idempotência** — mesmo `id` devolve a análise já gravada.
2. **Freshness da denylist** — frio fala com a mock; quente só lê `document_block`.
3. Se pagador ou recebedor está bloqueado → `rejected` (`decision_reason: document_blocked`).
4. Avalia todas as regras do rule set ativo → `triggered_mask`, `score`, `triggered_rules`.
5. Se algum **pattern crítico** é submáscara do mask → `rejected` (`critical_pattern_matched`).
6. Se `score >= score_threshold_2fa` (**40**) → `two_factor_required`.
7. Senão → `approved`.

Resposta: `{ "key", "status", "metadata" }`. O metadata traz máscara, regras, score, limiar de 2FA, motivo e pattern casado (se houver).

| triggered | resultado |
|-----------|-----------|
| exatamente os bits do pattern | reject |
| pattern + bits extras | reject (superset) |
| faltou um bit do pattern | não casa → 2FA ou approved conforme score |

---

## Como rodar e testar

### Subir API + banco

```bash
docker compose up
```

API em http://localhost:3000. Token padrão: header `INTERNAL-TOKEN: default_token`.

### Exemplo de análise

```bash
curl -s -X POST http://localhost:3000/pix/transaction \
  -H "Content-Type: application/json" \
  -H "INTERNAL-TOKEN: default_token" \
  -d '{
    "id": "pix-demo-001",
    "amount": 15000,
    "transaction_date": "2026-10-17T14:15:00-03:00",
    "source_account": {
      "branch": "0001",
      "account_number": "88213",
      "opening_date": "2020-03-02T10:00:00-03:00",
      "owner": { "document_number": "123.456.789-09" }
    },
    "destination_account": {
      "participant": "60701190",
      "branch": "3675",
      "account_number": "10442",
      "opening_date": "2020-10-10T09:00:00-03:00",
      "owner": { "document_number": "987.654.321-00" }
    },
    "source": {
      "device_id": "dvc-demo",
      "channel": "app",
      "ip": "198.51.100.23",
      "geolocation": { "latitude": -23.56, "longitude": -46.65 }
    }
  }'
```

Consulta: `GET /pix/transaction/pix-demo-001` com o mesmo token.

### Testes

Na máquina host (API no Docker):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r tests/requirements.txt
pytest
```

Suites: contrato HTTP, motor de decisão (patterns/score), denylist/freshness, e cobertura 1:1 das regras/patterns do seed.

Mock de condenação (path frio): sobe nos testes em `tests/utils/fraud_registry_mock.py` (porta 8765). A API no Docker aponta para `http://host.docker.internal:8765`.
