#!/usr/bin/env python3
"""One-shot API integration test against a running local Docker deployment (uses stdlib)."""
import json
import os
import time
import urllib.error
import urllib.request

ROOT = os.environ.get("DUTY_URL", "http://localhost:8080")+"/api/v1"
PASSWORD = os.environ.get("DEMO_PASSWORD", "DemoPass123!")
TOKEN = None

def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Accept":"application/json"}
    if payload is not None: headers["Content-Type"] = "application/json"
    if TOKEN: headers["Authorization"]="Bearer "+TOKEN
    req=urllib.request.Request(ROOT+path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req,timeout=12) as response:
        return json.load(response)

def wait_for(predicate, description, timeout=65):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            result=predicate()
            if result:return result
        except (KeyError,urllib.error.HTTPError,urllib.error.URLError):pass
        time.sleep(3)
    raise AssertionError("Timed out: "+description)

def main():
    global TOKEN
    TOKEN=api("POST","/auth/login",{"username":"admin","password":PASSWORD})["access_token"]
    print("PASS authentication")
    api("POST","/demo/reset")
    # allow any previous active Prometheus alert to clear first
    time.sleep(15)
    api("POST","/demo/scenarios/cpu_high/trigger")
    incident=wait_for(lambda: next((i for i in api("GET","/incidents?page_size=100")["items"] if i["alert_name"]=="HighCPUUsage" and i["monitor_state"]=="firing"),None),"CPU alert")
    uid=incident["id"]
    print("PASS Prometheus -> incident",uid)
    detail=wait_for(lambda: (d if (d:=api("GET","/incidents/"+uid))["latest_analysis"] and d["latest_analysis"]["status"]=="completed" else None),"AI inference")
    assert (detail["severity"],detail["category"],detail["priority"]) == ("critical","server","P1")
    print("PASS AI classification",detail["latest_analysis"]["confidence"])
    recommendations=wait_for(lambda: api("GET","/incidents/"+uid+"/recommendations")["items"],"runbook suggestion")
    assert recommendations[0]["steps_snapshot"]
    print("PASS runbook retrieval", recommendations[0]["runbook_title"])
    api("POST","/incidents/"+uid+"/acknowledge")
    checklist=api("POST",f"/incidents/{uid}/recommendations/{recommendations[0]['id']}/adopt")["items"]
    assert checklist
    for step in checklist:
        api("PATCH",f"/incidents/{uid}/checklist/{step['id']}",{"status":"done","note":"Проверено вручную при тестировании"})
    print("PASS human-only checklist")
    api("POST","/demo/reset")
    wait_for(lambda:(d if (d:=api("GET","/incidents/"+uid))["monitor_state"]=="resolved" else None),"Prometheus resolved state",timeout=90)
    result=api("POST","/incidents/"+uid+"/close",{"resolution_note":"Тестовое событие завершилось после сброса метрики; ручная проверка пройдена"})
    assert result["workflow_status"]=="closed"
    timeline=api("GET","/incidents/"+uid+"/timeline")["items"]
    assert any(x["action"]=="incident.closed" for x in timeline)
    print("PASS recovery, incident closure and audit trail")
    print("SMOKE TEST PASSED")

if __name__=="__main__": main()
