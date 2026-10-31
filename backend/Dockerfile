FROM python:3.12-slim
WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 libgomp1 && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
# Real neural E5 retrieval enabled for the default Docker demo.
# CPU-only Torch avoids multi-GB CUDA wheels and requires no GPU.
ARG INSTALL_E5=1
COPY backend/requirements-ai-optional.txt ./requirements-ai-optional.txt
RUN if [ "$INSTALL_E5" = "1" ]; then \
    pip install --no-cache-dir torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements-ai-optional.txt && \
    python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('intfloat/multilingual-e5-small')"; \
    fi
# E5 weights are baked into the image: runtime inference does not require an AI API.
ENV HF_HUB_OFFLINE=1
COPY backend/app ./app
# Offline ML training: no network access required beyond installing Python dependencies.
# Do not include final holdout rule snapshots in the runtime image.
RUN mkdir -p /srv/ml_fixtures
COPY backend/tests/fixtures/public_prometheus_rules.csv /srv/ml_fixtures/
COPY backend/tests/fixtures/heldout_prometheus_rules.csv /srv/ml_fixtures/
COPY backend/tests/fixtures/ml_v14_source_part0.csv /srv/ml_fixtures/
COPY backend/tests/fixtures/ml_v14_source_part1.csv /srv/ml_fixtures/
COPY backend/tests/fixtures/ml_v14_source_part2.csv /srv/ml_fixtures/
RUN python -m app.ml_v14 --train --fixtures /srv/ml_fixtures
# No holdout snapshot is copied into the runtime build context.
RUN mkdir -p /srv/context_fixtures
COPY backend/tests/fixtures/ml_v16_train.csv /srv/context_fixtures/
COPY backend/tests/fixtures/ml_v16_validation.csv /srv/context_fixtures/
RUN python -m app.ml_v16 --train --fixtures /srv/context_fixtures
COPY contracts/openapi.yaml ./contracts/openapi.yaml
COPY scripts/reindex_embeddings.py ./reindex_embeddings.py
EXPOSE 8000
