import json,subprocess,urllib.request,urllib.error
BASE='http://127.0.0.1:8084'
c=json.loads(subprocess.check_output(['docker','inspect','nhost-hasura-isolation-stage'],text=True))[0]
env=dict(x.split('=',1) for x in c['Config']['Env'] if '=' in x)
secret=env['HASURA_GRAPHQL_ADMIN_SECRET']
def meta(op,args):
    data=json.dumps({'type':op,'args':args}).encode()
    req=urllib.request.Request(BASE+'/v1/metadata',data=data,headers={'Content-Type':'application/json','x-hasura-admin-secret':secret})
    try:
        with urllib.request.urlopen(req,timeout=30) as res: return json.load(res)
    except urllib.error.HTTPError as e:
        body=e.read().decode(errors='replace')
        print('STAGE_METADATA_FAILED='+op+'; HTTP '+str(e.code)+'; '+body[:500])
        raise SystemExit(2)
# Ensure metadata reader can inspect private membership table. Clone database only.
subprocess.run(['docker','compose','exec','-T','postgres','psql','-v','ON_ERROR_STOP=1','-U','postgres','-d','appdb_project_stage_20261110','-c',
'GRANT USAGE ON SCHEMA platform, public TO hasura_admin; GRANT SELECT ON ALL TABLES IN SCHEMA platform TO hasura_admin; GRANT SELECT ON ALL TABLES IN SCHEMA public TO hasura_admin;'],check=True,stdout=subprocess.DEVNULL)
tables={
 'platform.project_memberships':None,
 'public.campaigns':['id','slug','title','description','short_description','cover_image_file_id','category','target_amount_minor','currency_code','state','starts_at','ends_at','display_order','is_featured'],
 'public.events':['id','slug','title','description','short_description','banner_file_id','starts_at','ends_at','timezone','venue','state','published_at','completed_at','is_featured','display_order'],
 'public.galleries':['id','slug','title','description','cover_image_file_id','state','display_order','is_featured','published_at'],
 'public.gallery_images':['id','gallery_id','file_asset_id','title','caption','alt_text','photographer_credit','taken_at','display_order','is_featured','state','published_at'],
 'public.static_pages':['id','slug','title','meta_description','body_json','body_html','state','is_homepage','display_order','published_at','last_published_at','homepage_content','about_page_content','legal_page_content'],
 'public.campaign_progress':['project_id','campaign_id','currency_code','raised_amount_minor','completed_donation_count','unique_donor_count']
}
for key in tables:
    schema,name=key.split('.')
    meta('pg_track_table',{'source':'default','table':{'schema':schema,'name':name}})
for key in ['public.campaigns','public.events','public.galleries','public.gallery_images','public.static_pages','public.campaign_progress']:
    schema,name=key.split('.')
    meta('pg_create_array_relationship',{'source':'default','table':{'schema':schema,'name':name},'name':'project_memberships','using':{'manual_configuration':{'remote_table':{'schema':'platform','name':'project_memberships'},'column_mapping':{'project_id':'project_id'}}}})
# gallery_images must only be public while its parent gallery is published
meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'gallery_images'},'name':'gallery','using':{'manual_configuration':{'remote_table':{'schema':'public','name':'galleries'},'column_mapping':{'project_id':'project_id','gallery_id':'id'}}}})
base_filters={
 'campaigns':{'state':{'_in':['active','completed']},'deleted_at':{'_is_null':True}},
 'events':{'state':{'_in':['published','completed']},'published_at':{'_is_null':False},'deleted_at':{'_is_null':True}},
 'galleries':{'state':{'_eq':'published'},'published_at':{'_is_null':False},'deleted_at':{'_is_null':True}},
 'gallery_images':{'state':{'_eq':'published'},'published_at':{'_is_null':False},'deleted_at':{'_is_null':True},'gallery':{'state':{'_eq':'published'},'published_at':{'_is_null':False},'deleted_at':{'_is_null':True}}},
 'static_pages':{'state':{'_eq':'published'},'published_at':{'_is_null':False},'deleted_at':{'_is_null':True}},
 'campaign_progress':{}
}
def and_filter(*parts): return {'_and':list(parts)}
for key,columns in tables.items():
 if not columns: continue
 schema,name=key.split('.')
 for role in ['client_public','user','service_reader']:
  if role=='user':
   scope={'project_memberships':{'user_id':{'_eq':'X-Hasura-User-Id'},'status':{'_eq':'active'}}}
  else:
   scope={'project_id':{'_eq':'X-Hasura-Project-Id'}}
  filt=and_filter(scope,base_filters[name])
  meta('pg_create_select_permission',{'source':'default','table':{'schema':schema,'name':name},'role':role,'permission':{'columns':columns,'filter':filt,'limit':100,'allow_aggregations':False}})
print('STAGE_METADATA=APPLIED; tables='+str(len(tables))+'; roles=client_public,user,service_reader; mutations=none')

