#!/usr/bin/env python3
"""Evaluates rule-based classifier. Synthetic, not production and not LLM accuracy.
Command: docker compose exec api python /srv/evaluate_ai.py
"""
import json
from collections import Counter
from app.ai import classify
from tests.test_ai import DATA
from tests.holdout_cases import HOLDOUT

def evaluate(data, name):
    correct_category=correct_severity=joint=0
    errors=[]
    for alert_name,description,category,severity in data:
        result=classify({"alert_name":alert_name,"description":description,"labels":{}})
        good_category=result['category']==category
        good_severity=result['severity']==severity
        correct_category+=good_category
        correct_severity+=good_severity
        joint+=good_category and good_severity
        if not (good_category and good_severity):
            errors.append({"alert":alert_name,"expected":f"{category}/{severity}","predicted":f"{result['category']}/{result['severity']}"})
    count=len(data)
    results={"dataset":name,"samples":count,"category_accuracy":round(correct_category/count,4),"severity_accuracy":round(correct_severity/count,4),"joint_accuracy":round(joint/count,4),"incorrect":errors}
    print(f"{name}: {count} SYNTHETIC cases (not production)")
    print(f"  category {correct_category}/{count}={correct_category/count:.1%}; severity {correct_severity}/{count}={correct_severity/count:.1%}; joint {joint}/{count}={joint/count:.1%}")
    for err in errors: print("  ERROR", err)
    return results

def main():
    a=evaluate(DATA,'Original synthetic benchmark')
    b=evaluate(HOLDOUT,'Additional manually written synthetic holdout')
    print('Result (JSON):',json.dumps({"original":a,"additional":b},ensure_ascii=False))
    print('NOTE: these are manually authored synthetic samples; do not report them as external independent validation.')
    if a['joint_accuracy']<.90 or b['joint_accuracy']<.90:
        raise SystemExit('FAILED: joint accuracy below 90% on one synthetic split')
    print('PASS: both synthetic evaluation splits >=90%')
if __name__=='__main__': main()
