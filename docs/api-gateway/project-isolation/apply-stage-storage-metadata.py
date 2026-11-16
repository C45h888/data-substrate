import json,subprocess,urllib.request,urllib.error,os
BASE='http://127.0.0.1:8084'
c=json.loads(subprocess.check_output(['docker','inspect','nhost-hasura-isolation-stage'],text=True))[0]
env=dict(x.split('=',1) for x in c['Config']['Env'] if '=' in x);secret=env['HASURA_GRAPHQL_ADMIN_SECRET']
def api(payload):
 req=urllib.request.Request(BASE+'/v1/metadata',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','x-hasura-admin-secret':secret})
 try:
  with urllib.request.urlopen(req,timeout=30) as r:return json.load(r)
 except urllib.error.HTTPError as e:
  print('STAGE_STORAGE_METADATA_FAILED='+payload.get('type','?')+'; HTTP='+str(e.code)+'; '+e.read().decode(errors='replace')[:500]);raise SystemExit(2)
def meta(op,args):return api({'type':op,'args':args})
from pathlib import Path
db=str(Path(__file__).resolve().parents[3])
subprocess.run(['docker','compose','exec','-T','postgres','psql','-v','ON_ERROR_STOP=1','-U','postgres','-d','appdb_project_stage_20261110','-c','GRANT USAGE ON SCHEMA platform,storage TO hasura_admin; GRANT SELECT ON ALL TABLES IN SCHEMA platform,storage TO hasura_admin;'],cwd=db,check=True,stdout=subprocess.DEVNULL)
m=api({'type':'export_metadata','args':{}})
tracked={(s['name'],t['table']['schema'],t['table']['name']):t for s in m.get('sources',[]) for t in s.get('tables',[])}
for schema,name in [('storage','buckets'),('storage','files'),('platform','project_storage_buckets')]:
 if ('default',schema,name) not in tracked:meta('pg_track_table',{'source':'default','table':{'schema':schema,'name':name}})
m=api({'type':'export_metadata','args':{}})
tracked={(s['name'],t['table']['schema'],t['table']['name']):t for s in m.get('sources',[]) for t in s.get('tables',[])}
b=tracked[('default','storage','buckets')]
if not any(x['name']=='project_storage_project' for x in b.get('object_relationships',[])):
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'storage','name':'buckets'},'name':'project_storage_project','using':{'manual_configuration':{'remote_table':{'schema':'platform','name':'project_storage_buckets'},'column_mapping':{'id':'bucket_id'}}}})
mp=tracked[('default','platform','project_storage_buckets')]
if not any(x['name']=='project_memberships' for x in mp.get('array_relationships',[])):
 meta('pg_create_array_relationship',{'source':'default','table':{'schema':'platform','name':'project_storage_buckets'},'name':'project_memberships','using':{'manual_configuration':{'remote_table':{'schema':'platform','name':'project_memberships'},'column_mapping':{'project_id':'project_id'}}}})
files=tracked[('default','storage','files')]
if not any(x['name']=='bucket' for x in files.get('object_relationships',[])):
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'storage','name':'files'},'name':'bucket','using':{'manual_configuration':{'remote_table':{'schema':'storage','name':'buckets'},'column_mapping':{'bucket_id':'id'}}}})
m=api({'type':'export_metadata','args':{}})
files=next(t for s in m['sources'] if s['name']=='default' for t in s['tables'] if t['table']=={'schema':'storage','name':'files'})
for kind in ('select_permissions','insert_permissions','delete_permissions'):
 for p in files.get(kind,[]):
  if p['role']=='user':
   opname={'select_permissions':'pg_drop_select_permission','insert_permissions':'pg_drop_insert_permission','delete_permissions':'pg_drop_delete_permission'}[kind]
   meta(opname,{'source':'default','table':{'schema':'storage','name':'files'},'role':'user'})
scope={'bucket':{'project_storage_project':{'project_memberships':{'user_id':{'_eq':'X-Hasura-User-Id'},'status':{'_eq':'active'}}}}}
default={'bucket_id':{'_eq':'default'}}
owner={'uploaded_by_user_id':{'_eq':'X-Hasura-User-Id'}}
combined={'_and':[owner,{'_or':[default,scope]}]}
meta('pg_create_select_permission',{'source':'default','table':{'schema':'storage','name':'files'},'role':'user','permission':{'columns':['id','created_at','updated_at','bucket_id','name','size','mime_type','etag','is_uploaded','uploaded_by_user_id','metadata'],'filter':combined}})
meta('pg_create_insert_permission',{'source':'default','table':{'schema':'storage','name':'files'},'role':'user','permission':{'columns':['id','bucket_id','name','size','mime_type','metadata'],'set':{'uploaded_by_user_id':'X-Hasura-User-Id'},'check':{'_or':[default,scope]}}})
meta('pg_create_delete_permission',{'source':'default','table':{'schema':'storage','name':'files'},'role':'user','permission':{'filter':combined}})
print('STAGE_STORAGE_PROJECT_PERMISSION_METADATA=APPLIED; default=preserved; project=membership_plus_uploader')

