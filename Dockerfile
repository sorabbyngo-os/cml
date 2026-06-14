# CML — Cognitive Mediation Layer
# Standalone NATS service — safety filter, privacy enforcer, audit ledger
# Build: docker build -t cml-service .
# Run:   docker run --network host --env-file .env cml-service

FROM python:3.12-slim

LABEL org.opencontainers.image.title="CML Service"
LABEL org.opencontainers.image.description="Sorabbyngo Cognitive Mediation Layer — safety, privacy, audit"
LABEL org.opencontainers.image.vendor="Sorabbyngo Company"
LABEL org.opencontainers.image.source="https://github.com/sorabbyngo-Labs/cml"

WORKDIR /opt/cml

COPY requirements.txt* ./
RUN pip install --no-cache-dir nats-py 2>/dev/null || true

COPY . .

RUN mkdir -p /etc/sorabbyngo/cml
VOLUME ["/etc/sorabbyngo/cml"]

ENV NATS_URL=nats://localhost:4222
ENV CML_LEDGER_PATH=/etc/sorabbyngo/cml/audit.jsonl
ENV CML_FAIL_OPEN=true
ENV HOSPITAL_REGION=KE047
ENV LOG_LEVEL=INFO

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "from filters.safety import SafetyFilter; SafetyFilter().check('test'); print('ok')" || exit 1

CMD ["python3", "cml_service.py"]
