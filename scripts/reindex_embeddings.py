"""Maintenance: recompute every runbook vector using EMBEDDING_BACKEND=e5.
Only run with sentence-transformers installed; see upgrade guide.
"""
from sqlalchemy import select
from app.database import SessionLocal
from app.models import Runbook
from app.ai import embed
from app.config import settings

def main():
    if settings.embedding_backend!='e5':
        raise SystemExit('Refusing to reindex: EMBEDDING_BACKEND must equal e5')
    with SessionLocal() as db:
        books=db.scalars(select(Runbook).order_by(Runbook.id)).all()
        print(f'Reindexing {len(books)} runbooks for neural E5 embeddings')
        for runbook in books:
            runbook.embedding=embed(f'{runbook.title} {runbook.condition_text}',kind='passage')
        db.commit()
        print('DONE: all runbook vectors reindexed')
if __name__=='__main__':main()
