"""Lifecycle guards protecting history, without requiring a running DB."""
from types import SimpleNamespace
from uuid import UUID
import pytest
from fastapi import HTTPException
pytest.importorskip("redis", reason="Integration API tests require backend/requirements.txt")
pytest.importorskip("celery")
pytest.importorskip("pgvector")
from app import main

ID=UUID('00000000-0000-0000-0000-000000000001')

class DB:
    def __init__(self,used=None): self.used=used;self.deleted=[];self.commits=0
    def scalar(self,query): return self.used
    def delete(self,item): self.deleted.append(item)
    def commit(self): self.commits+=1

def test_restore_archived(monkeypatch):
    runbook=SimpleNamespace(id=str(ID),version=2,is_active=False)
    monkeypatch.setattr(main,'get_runbook',lambda *args,**kw:runbook)
    monkeypatch.setattr(main,'runbook_json',lambda r:{'version':r.version,'is_active':r.is_active})
    db=DB()
    assert main.restore_runbook(ID,db=db,_=None)=={'version':3,'is_active':True}
    assert db.commits==1

def test_restore_active_rejected(monkeypatch):
    monkeypatch.setattr(main,'get_runbook',lambda *a,**k:SimpleNamespace(is_active=True))
    with pytest.raises(HTTPException) as exc: main.restore_runbook(ID,db=DB(),_=None)
    assert exc.value.status_code==409

def test_purge_active_rejected(monkeypatch):
    monkeypatch.setattr(main,'get_runbook',lambda *a,**k:SimpleNamespace(is_active=True))
    with pytest.raises(HTTPException) as exc: main.purge_runbook(ID,db=DB(),_=None)
    assert exc.value.status_code==409

def test_purge_referenced_rejected(monkeypatch):
    monkeypatch.setattr(main,'get_runbook',lambda *a,**k:SimpleNamespace(is_active=False,id=str(ID)))
    db=DB(used='recommendation_id')
    with pytest.raises(HTTPException) as exc: main.purge_runbook(ID,db=db,_=None)
    assert exc.value.status_code==409 and db.deleted==[]

def test_purge_archived_unreferenced(monkeypatch):
    runbook=SimpleNamespace(is_active=False,id=str(ID))
    monkeypatch.setattr(main,'get_runbook',lambda *a,**k:runbook)
    db=DB()
    response=main.purge_runbook(ID,db=db,_=None)
    assert response.status_code==204 and db.deleted==[runbook] and db.commits==1
