"""Isolated real-DB/Trivy/Java HTTP acceptance. No production Compose is changed."""
import argparse, calendar, hashlib, http.cookiejar, io, json, os, subprocess, time, urllib.request, urllib.error, uuid, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'.cache/sca'
RUNTIME=OUT/os.environ.get('SCA_TEST_RUNTIME','runtime')
STORAGE=RUNTIME/'storage'
PORT=os.environ.get('SCA_TEST_PORT','18084')
BASE='http://127.0.0.1:'+PORT
LABEL='binaryscan.sca-test'
DB_CONTAINER=os.environ.get('SCA_TEST_DB_CONTAINER','binaryscan-sca-mysql')
PREFIX=os.environ.get('SCA_TEST_PREFIX','binaryscan-sca')
NAMES={key:PREFIX+'-'+key for key in ['app','scanner','java']}
NETWORK='binaryscan-sca-offline'
def docker(args,**kw): return subprocess.run(['docker',*args],capture_output=True,check=True,**kw)
def setup():
    OUT.mkdir(parents=True,exist_ok=True)
    info=json.loads(docker(['inspect',DB_CONTAINER]).stdout)[0]
    if info['Config'].get('Labels',{}).get(LABEL)!='true': raise RuntimeError('Not the labelled fixture database')
    docker(['exec','-e','MYSQL_PWD=sca-test-only',DB_CONTAINER,'mysql','-uroot','sca_test','-e',"DELETE j FROM jobs j JOIN runs r ON r.id=j.run_id JOIN tasks t ON t.id=r.task_id WHERE t.display_name='fixture';"])
    try: docker(['network','inspect',NETWORK])
    except subprocess.CalledProcessError: docker(['network','create','--internal','--label',LABEL+'=true',NETWORK])
    try: docker(['network','connect',NETWORK,DB_CONTAINER])
    except subprocess.CalledProcessError: pass
    for name in NAMES.values():
        try: info=json.loads(docker(['inspect',name]).stdout)[0]
        except subprocess.CalledProcessError: continue
        if info['Config'].get('Labels',{}).get(LABEL)!='true': raise RuntimeError('Unowned fixture container '+name)
        docker(['rm','-f',name])
    for name in ['blobs','uploads','projects','artifacts','reports']: (STORAGE/name).mkdir(parents=True,exist_ok=True)
    common=['--label',LABEL+'=true','--network',NETWORK,'--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=512m,mode=1777']
    docker(['run','-d','--name',NAMES['java'],*common,'--memory','2g','binaryscan/java-checker:sca-20261117'])
    db={'BINARY_DB_HOST':DB_CONTAINER,'BINARY_DB_PORT':'3306','BINARY_DB_NAME':'sca_test','BINARY_DB_USER':'root','BINARY_DB_PASSWORD':'sca-test-only'}
    def env(values): return [x for k,v in values.items() for x in ['-e',k+'='+v]]
    app={**db,'BINARY_ROLE':'app','BINARY_VERSION':'sca-20261117','BINARY_LISTEN_ADDR':'0.0.0.0:8080','BINARY_PUBLIC_BASE_URL':BASE,'BINARY_ALLOWED_ORIGINS':BASE+',http://localhost:18084','BINARY_INITIAL_ADMIN_USERNAME':'sca-review','BINARY_INITIAL_ADMIN_PASSWORD':'SCA-review-2026!','BINARY_STORAGE_ROOT':'/data/storage'}
    app_common=['--label',LABEL+'=true','--network','binaryscan-sca-test','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=512m,mode=1777']
    docker(['run','-d','--name',NAMES['app'],*app_common,'--memory','1g','-p','127.0.0.1:'+PORT+':8080','-v',str(STORAGE)+':/data/storage',*env(app),'binaryscan/app:sca-20261117'])
    docker(['network','connect',NETWORK,NAMES['app']])
    worker={**db,'BINARY_ROLE':'scanner','BINARY_VERSION':'sca-20261117','BINARY_BLOB_ROOT':'/data/storage/blobs','BINARY_PROJECT_ROOT':'/data/storage/projects','BINARY_ARTIFACT_ROOT':'/data/storage/artifacts','BINARY_WORK_ROOT':'/data/work','BINARY_JAVA_CHECKER_URL':'http://'+NAMES['java']+':8080','BINARY_TRIVY_PATH':'/usr/local/bin/trivy','BINARY_TRIVY_CACHE_ROOT':'/opt/trivy-cache','BINARY_JOB_POLL_MILLISECONDS':'100','BINARY_CAPABILITY_PROBE_SECONDS':'300'}
    (RUNTIME/'work').mkdir(exist_ok=True)
    docker(['run','-d','--name',NAMES['scanner'],*common,'--memory','2g','-v',str(STORAGE)+':/data/storage','-v',str(RUNTIME/'work')+':/data/work',*env(worker),'binaryscan/scanner:sca-20261117'])
    for _ in range(120):
        try:
            if urllib.request.urlopen(BASE+'/readyz',timeout=2).status==200:break
        except (OSError,urllib.error.URLError):time.sleep(1)
    else: raise RuntimeError('Fixture App not ready: '+docker(['logs',NAMES['app']]).stdout.decode())
    docker(['exec','-e','MYSQL_PWD=sca-test-only',DB_CONTAINER,'mysql','-uroot','sca_test','-e',"UPDATE users SET must_change_password=0 WHERE username='sca-review';"])
    print('Isolated services ready',BASE,flush=True)
def client():return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
OPENER=None;CSRF=''
def req(path,method='GET',data=None,raw=None,extra=None,expect=(200,201,202,204)):
    headers={'Accept':'application/json','X-CSRF-Token':CSRF,'Idempotency-Key':str(uuid.uuid4())}
    if extra:headers.update(extra)
    if raw is not None:payload=raw
    else:payload=None if data is None else json.dumps(data).encode();headers['Content-Type']='application/json'
    request=urllib.request.Request(BASE+'/api/v1'+path,data=payload,headers=headers,method=method)
    try:r=OPENER.open(request,timeout=30)
    except urllib.error.HTTPError as e:r=e
    body=r.read()
    if r.status not in expect: raise AssertionError((path,r.status,body[:2000].decode(errors='replace')))
    return json.loads(body) if body and ('json' in r.headers.get('Content-Type','')) else body
def upload(name,mode):
    data=(ROOT/'test-fixtures/sca'/name).read_bytes();h=hashlib.sha256(data).hexdigest()
    u=req('/uploads','POST',{'filename':name,'size':len(data),'content_type':'application/octet-stream'});uid=u['id']
    req('/uploads/'+uid+'/parts/1','PUT',raw=data,extra={'Content-Type':'application/octet-stream','Content-Range':f'bytes 0-{len(data)-1}/{len(data)}','X-Chunk-SHA256':h})
    req('/uploads/'+uid+'/complete','POST',{'sha256':h})
    t=req('/uploads/'+uid+'/tasks','POST',{'analysis_mode':mode});return t['task_id']
def wait_scan(task,previous=None):
    for _ in range(180):
        o=req('/tasks/'+task+'/inventories');scans=[r for r in o['runs'] if r['kind']=='sca_scan']
        failed=[r for r in o['runs'] if r['status']=='failed']
        if failed:raise AssertionError(('scan failed',failed))
        if scans and scans[0]['id']!=previous and scans[0]['status'] in ['complete','partial']:
            run=scans[0];inv=run['inventoryId'] or next(i['id'] for i in o['items'] if i['runId']==run['id']);return o,run['id'],inv
        time.sleep(1)
    raise AssertionError('scan timeout '+task)
def analyze(task,run,inventory,env,mode='automatic'):
    policy=req('/tasks/'+task+'/analysis-policies','POST',{'mode':mode,'validHours':24,'reachability':True,'environment':True,'attack':True})['item']['id']
    r=req('/tasks/'+task+'/impact-analyses','POST',{'scaRunId':run,'inventoryId':inventory,'environmentVersionId':env,'policyId':policy})['run']['id']
    for _ in range(200):
        result=req('/tasks/'+task+'/impact-analyses/'+r)
        if result['status']=='failed':raise AssertionError(('impact failed',req('/tasks/'+task+'/inventories')))
        if result['status'] in ['complete','partial']:return r,result
        time.sleep(1)
    raise AssertionError('impact timeout')
def verify():
    global OPENER,CSRF
    OPENER=client();login=req('/auth/login','POST',{'username':'sca-review','password':'SCA-review-2026!'});CSRF=login['user']['csrfToken']
    env=req('/environment-profiles','POST',{'config':{'name':'SCA acceptance Java 8 '+uuid.uuid4().hex[:8],'javaRelease':8,'applicationType':'java','entryPoints':[],'externalDependencies':[],'facts':{}},'expectedRevision':0})['item']
    result={'baseUrl':BASE,'databaseContainer':DB_CONTAINER,'environment':env,'cases':[],'tasks':{}}
    for name in ['spdx.json','spdx.spdx','cyclonedx-1.4.json','cyclonedx-1.5.json','cyclonedx-1.6.json','cyclonedx-1.4.xml','cyclonedx-1.5.xml','cyclonedx-1.6.xml','swid.xml']:
        task=upload(name,'sbom');overview,run,inventory=wait_scan(task);v=req('/tasks/'+task+'/vulnerability-occurrences');assert any(o['vulnerability']['id']=='CVE-2022-42889' for o in v['items']),(name,v)
        result['cases'].append({'case':name,'task':task,'vulnerabilities':v['summary']});print('PASS format',name,flush=True)
    for name in ['spdx-2.3.1-official.json','spdx-2.3.1-official.spdx']:
        task=upload(name,'sbom');overview,_,_=wait_scan(task);assert overview['items'][0]['document']['specVersion']=='SPDX-2.3' and overview['items'][0]['componentCount']>0
        result['cases'].append({'case':name,'task':task});print('PASS official SPDX 2.3.1 example',name,flush=True)
    collection_task=upload('swid-app.xml','sbom');root,old_run,_=wait_scan(collection_task)
    library_task=upload('swid.xml','sbom');library,_,_=wait_scan(library_task)
    members=[]
    for task,overview,name in [(collection_task,root,'swid-app.xml'),(library_task,library,'swid.xml')]:
        inv=overview['items'][0];members.append({'taskId':task,'inventoryId':inv['id'],'fingerprint':inv['document']['fingerprint'],'logicalPath':name})
    req('/tasks/'+collection_task+'/swid-collections','POST',{'swidMembers':members,'identityMappings':{'binaryscan:demo:1':'pkg:maven/local.fixture/demo@1'}})
    overview,_,_=wait_scan(collection_task,old_run);assert overview['items'][0]['dependencyCount']==1
    assert any(o['vulnerability']['id']=='CVE-2022-42889' for o in req('/tasks/'+collection_task+'/vulnerability-occurrences')['items'])
    print('PASS explicit SWID collection, identity mapping and local relation',flush=True)
    result['cases'].append({'case':'swid-explicit-collection','task':collection_task})
    for variant in ['reachable','unreachable','reflective']:
        for layout in ['plain','boot','war']:
            name=variant+'-'+layout+('.war' if layout=='war' else '.jar');task=upload(name,'java_sca');overview,run,inventory=wait_scan(task)
            analysis,answer=analyze(task,run,inventory,env['id']);states=[a for a in answer['items'] if a['code'].get('ruleId')=='apache-commons-text-interpolation-v1'];assert len(states)==1,(name,answer)
            expected={'reachable':'reachable','unreachable':'not_reachable','reflective':'unknown'}[variant];assert states[0]['reachability']==expected,(name,states)
            v=req('/tasks/'+task+'/vulnerability-occurrences');text=next(o for o in v['items'] if o['vulnerability']['id']=='CVE-2022-42889');assert text['status']==('ignored' if variant=='unreachable' else 'open'),(name,text)
            result['tasks'][name]=task;result['cases'].append({'case':name,'task':task,'analysis':analysis,'state':expected,'status':text['status']});print('PASS bytecode',name,expected,flush=True)
            if variant=='unreachable' and layout=='boot':
                future=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()+86400));scope=text['dispositions'][0]
                req('/tasks/'+task+'/vulnerability-occurrences/'+text['id']+'/disposition','POST',{'environmentVersionId':env['id'],'status':'open','expectedRevision':scope['revision'],'reason':'SCA acceptance restore override','overrideUntil':future,'expiresAt':None})
                analyze(task,run,inventory,env['id']);current=req('/tasks/'+task+'/vulnerability-occurrences/'+text['id'])['item'];assert current['status']=='open','manual restore overwritten'
                for format in ['json','html','docx']:
                    report=req('/tasks/'+task+'/reports','POST',{'format':format,'runIds':[run,analysis]})['report'];content=req('/reports/'+report['id']+'/content')
                    if format=='json':assert content['schema']=='binaryscan-report-v5' and content['sca']['summary']['open']>=1
                    elif format=='html':assert '组件漏洞与三维影响分析'.encode() in content
                    else:assert '组件漏洞与三维影响分析' in zipfile.ZipFile(io.BytesIO(content)).read('word/document.xml').decode()
                print('PASS manual restore and JSON/HTML/DOCX snapshots',flush=True)
    verify_edges(result)
    network=json.loads(docker(['network','inspect',NETWORK]).stdout)[0];assert network['Internal'] is True
    result.update(status='passed',completedAt=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),analysisNetworkInternal=True,images={key:json.loads(docker(['inspect',name]).stdout)[0]['Image'] for key,name in NAMES.items()},fixturesManifestSHA256=hashlib.sha256((ROOT/'test-fixtures/sca/manifest.json').read_bytes()).hexdigest())
    (OUT/'acceptance.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Acceptance evidence:',OUT/'acceptance.json',flush=True)

def verify_edges(result):
    global OPENER,CSRF
    task=upload('log4j.json','sbom');_,run,inventory=wait_scan(task)
    def profile(name,verified,expires=None):
        fact={'value':'false','verified':verified,'evidence':'Acceptance fixture: full effective logging pattern captured for every instance' if verified else ''}
        if expires:fact['expiresAt']=expires
        return req('/environment-profiles','POST',{'expectedRevision':0,'config':{'name':name,'javaRelease':17,'applicationType':'java','entryPoints':[],'externalDependencies':[],'facts':{'log4j.contextLookupPattern':fact}}})['item']
    declared=profile('Log4j declaration only',False)
    _,a=analyze(task,run,inventory,declared['id']);log=next(x for x in a['items'] if x['reason']=='NO_RELIABLE_EXCLUSION' and x['environment']=='unknown');assert log['excluded'] is False
    future=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()+12))
    verified=profile('Log4j verified condition with expiry',True,future)
    analysis,a=analyze(task,run,inventory,verified['id']);assert any(x['environment']=='not_applicable' and x['excluded'] for x in a['items'])
    o=next(x for x in req('/tasks/'+task+'/vulnerability-occurrences')['items'] if x['vulnerability']['id']=='CVE-2021-45105')
    original_cvss=o['vulnerability'].get('cvss');scope=next(x for x in o['dispositions'] if x['profileId']==verified['profileId']);assert scope['status']=='ignored' and o['status']=='open','multi-environment aggregation hid an open environment'
    req('/tasks/'+task+'/vulnerability-occurrences/'+o['id']+'/disposition','POST',{'environmentVersionId':verified['id'],'status':'open','expectedRevision':scope['revision']+9,'reason':'test stale revision','overrideUntil':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()+3600))},expect=(409,))
    while time.time()<calendar.timegm(time.strptime(future,'%Y-%m-%dT%H:%M:%SZ'))+1:time.sleep(1)
    expired=req('/tasks/'+task+'/vulnerability-occurrences/'+o['id'])['item'];expired_scope=next(x for x in expired['dispositions'] if x['profileId']==verified['profileId']);assert expired_scope['status']=='open' and expired_scope['validity']!='valid'
    for _ in range(95):
        current=req('/tasks/'+task+'/vulnerability-occurrences/'+o['id'])['item']
        fresh=[x for x in current['assessments'] if x['environmentVersionId']==verified['id'] and x['runId']!=analysis]
        if fresh:
            assert fresh[0]['environment']=='unknown' and not fresh[0]['excluded'];break
        time.sleep(1)
    else:raise AssertionError('expiry did not schedule a fresh scope-specific analysis')
    assert current['vulnerability'].get('cvss')==original_cvss,'raw CVSS changed after analysis'
    changed={**verified['config'],'name':'Log4j environment revision 2','facts':{'log4j.contextLookupPattern':{'value':'true','verified':True,'evidence':'Acceptance updated full logging configuration'}}}
    revision=req('/environment-profiles/'+verified['profileId'],'PATCH',{'expectedRevision':verified['revision'],'config':changed})['item'];assert revision['revision']==2 and revision['id']!=verified['id']
    req('/environment-profiles/'+verified['profileId'],'PATCH',{'expectedRevision':verified['revision'],'config':changed},expect=(409,))
    req('/tasks/'+task+'/impact-analyses','POST',{'scaRunId':run,'inventoryId':inventory,'environmentVersionId':verified['id'],'policyId':req('/tasks/'+task+'/analysis-policies')['items'][0]['id']},expect=(409,))
    req('/environment-profiles','POST',{'expectedRevision':0,'config':changed},extra={'X-CSRF-Token':''},expect=(403,))
    username='sca-reader-'+uuid.uuid4().hex[:8]
    req('/admin/users','POST',{'username':username,'password':'SCA-reader-test-2026!','role':'reader'})
    docker(['exec','-e','MYSQL_PWD=sca-test-only',DB_CONTAINER,'mysql','-uroot','sca_test','-e',"UPDATE users SET must_change_password=0 WHERE username='"+username+"';"])
    admin,token=OPENER,CSRF
    try:
        OPENER=client();CSRF='';CSRF=req('/auth/login','POST',{'username':username,'password':'SCA-reader-test-2026!'})['user']['csrfToken']
        req('/analysis-capabilities');req('/tasks/'+task+'/vulnerability-occurrences')
        req('/tasks/'+task+'/sca-scans','POST',{},expect=(403,));req('/environment-profiles','POST',{'expectedRevision':0,'config':changed},expect=(403,))
        req('/tasks/'+task+'/vulnerability-occurrences/'+o['id']+'/disposition','POST',{},expect=(403,))
    finally:OPENER,CSRF=admin,token
    result['cases'].append({'case':'log4j-environment-expiry-permissions','task':task,'checks':['unverified-fact-unknown','verified-condition-excludes-only-mapped-CVE','multi-environment-open','revision-conflict','expiry-reopens','scope-specific-auto-reevaluation','environment-version-conflict','csrf-required','reader-read-only','raw-cvss-preserved']})
    print('PASS condition evidence, expiry/reassessment, environment revisions, multi-environment and read-only/CSRF permissions',flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['setup','verify']);args=p.parse_args();setup() if args.action=='setup' else verify()
if __name__=='__main__':main()
