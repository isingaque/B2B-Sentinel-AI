FROM python:3.12-slim
WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
# Optional real neural embeddings; disabled for the default, quick hackathon build.
ARG INSTALL_E5=0
COPY backend/requirements-ai-optional.txt ./requirements-ai-optional.txt
RUN if [ "$INSTALL_E5" = "1" ]; then pip install --no-cache-dir -r requirements-ai-optional.txt; fi
COPY backend/app ./app
COPY contracts/openapi.yaml ./contracts/openapi.yaml
COPY scripts/reindex_embeddings.py ./reindex_embeddings.py
EXPOSE 8000
