export type Severity = 'critical'|'warning'|'info'
export type Category = 'server'|'network'|'database'|'application'
export type Workflow = 'open'|'acknowledged'|'closed'
export type Monitor = 'pending'|'firing'|'resolved'
export type User = {id:string;username:string;role:'admin'|'operator'}
export type Incident = {id:string;source_id:string;source_name:string;alert_name:string;title:string;description:string;labels:Record<string,string>;annotations:Record<string,string>;monitor_state:Monitor;workflow_status:Workflow;severity:Severity|null;category:Category|null;priority:string|null;started_at:string;last_seen_at:string;resolved_at:string|null;acknowledged_at:string|null;acknowledged_by:string|null;closed_at:string|null;closed_by:string|null;resolution_note:string|null}
export type Analysis = {id:string;status:'pending'|'running'|'completed'|'failed';severity:Severity|null;category:Category|null;priority:string|null;confidence:number|null;review_required:boolean;explanation:string|null;model_version:string;error_code:string|null;created_at:string;completed_at:string|null}
export type ComparisonResult = {
  category: Category
  severity: Severity
  priority: string
  model_version: string
  explanation: string
  priority_explanation: string
  review_required: boolean
}
export type ClassificationComparison = {
  baseline: ComparisonResult
  ml: ComparisonResult
  differences: {category:boolean;severity:boolean;priority:boolean}
  comparison_kind: 'label_blind_text_only'
  used_inputs: string[]
  target_source_labels_excluded: boolean
  priority_policy_uses_environment: boolean
  is_accuracy_measurement: boolean
}
export type Checklist = {id:string;incident_id:string;recommendation_id:string;position:number;instruction:string;status:'pending'|'done'|'skipped';note:string|null;updated_by:string|null;updated_at:string|null}
export type IncidentDetail = Incident & {latest_analysis:Analysis|null;adopted_recommendation_id:string|null;checklist:Checklist[]}
export type Recommendation = {id:string;incident_id:string;runbook_id:string;runbook_version:number;runbook_title:string;score:number;reason:string;steps_snapshot:{position:number;instruction:string;is_risky:boolean}[];is_adopted:boolean;created_at:string}
export type Runbook = {id:string;title:string;condition_text:string;category:Category|null;severity:Severity|null;is_active:boolean;version:number;steps:{id:string;position:number;instruction:string;is_risky:boolean}[];created_at:string;updated_at:string}
export type Summary = {open:number;acknowledged:number;closed:number;critical_open:number;analysis_pending:number;source_connected:boolean;updated_at:string}
export type Source = {id:string;name:string;kind:string;health:string;last_polled_at:string|null;last_error:string|null;enabled:boolean}
export type Timeline = {id:string;incident_id:string;actor_username:string;action:string;before:Record<string,unknown>|null;after:Record<string,unknown>|null;created_at:string}

const BASE='/api/v1'
export class ApiError extends Error {constructor(public status:number, message:string){super(message)}}
const wait=(ms:number)=>new Promise<void>(resolve=>setTimeout(resolve,ms))
/** Only GETs can be retried automatically; never replay a mutating request. */
export async function api<T>(path:string, options:RequestInit={}):Promise<T>{
  const token=localStorage.getItem('duty_token')
  const headers: Record<string,string> = {}
  if(!(options.body instanceof FormData))headers['Content-Type']='application/json'
  if(token) headers['Authorization']=`Bearer ${token}`
  Object.assign(headers,options.headers||{})
  const method=(options.method||'GET').toUpperCase()
  const retries=method==='GET'?2:0
  for(let attempt=0;attempt<=retries;attempt++){
    let res:Response
    try {res=await fetch(BASE+path,{...options,headers})}
    catch {
      if(attempt<retries){await wait(350*(attempt+1));continue}
      throw new ApiError(0,'Сервер временно недоступен. Данные не удалены. Повторите запрос.')
    }
    if(!res.ok){
      if(attempt<retries&&[502,503,504].includes(res.status)){await wait(350*(attempt+1));continue}
      let msg=`Ошибка HTTP ${res.status}`
      try{const body=await res.json();msg=body.detail||msg}catch{/* no JSON */}
      if(res.status===401 && !path.includes('/auth/login')){
        localStorage.removeItem('duty_token');window.dispatchEvent(new Event('duty-logout'))
      }
      throw new ApiError(res.status,msg)
    }
    if(res.status===204)return undefined as T
    return res.json() as Promise<T>
  }
  throw new ApiError(0,'Сервер недоступен')
}

export const post=<T>(path:string,body?:unknown)=>api<T>(path,{method:'POST',...(body===undefined?{}:{body:JSON.stringify(body)})})
export const patch=<T>(path:string,body:unknown)=>api<T>(path,{method:'PATCH',body:JSON.stringify(body)})
export const del=(path:string)=>api<void>(path,{method:'DELETE'})
