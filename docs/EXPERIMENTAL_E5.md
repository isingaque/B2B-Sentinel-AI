# Experimental: neural embeddings (NOT enabled in standard v1.1)

The default v1.1 release stays with `EMBEDDING_BACKEND=hash` to preserve compatibility and fast startup. It has a *working opt-in path* for E5 neural vector search, but this optional mode has not been end-to-end Docker-tested in the authoring environment and may download several hundred MB of model libraries.

**Before attempting:** back up PostgreSQL, ensure internet during first model download, enough RAM/disk, and avoid performing the migration during the live demo.

1. Edit `.env`: set `INSTALL_E5=1` (leave `EMBEDDING_BACKEND=hash` for now).
2. Rebuild images: `docker compose build api worker scheduler`.
3. Stop background processing: `docker compose stop scheduler worker api`.
4. Run one-off reindex with e5: `docker compose run --rm -e EMBEDDING_BACKEND=e5 api python /srv/reindex_embeddings.py`.
5. After **DONE**, edit `.env`: `EMBEDDING_BACKEND=e5`.
6. Run `docker compose up -d api worker scheduler`.

**Important:** E5 query embeddings must be compared with E5 passage embeddings. Mixing hash and E5 in the existing `runbooks.embedding` column gives meaningless results. Always reindex all runbooks when switching encoding algorithms. Both use dimension 384. If the model cannot be downloaded or memory is insufficient, do not switch modes. This is not an external LLM: it improves retrieval only; classification remains rule-based.
