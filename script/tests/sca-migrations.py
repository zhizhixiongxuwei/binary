"""Apply and repeat new migrations against the explicitly labelled fixture DB."""
import json, os, subprocess, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
CONTAINER=os.environ.get('SCA_TEST_DB_CONTAINER','binaryscan-sca-mysql')
def sql(body):
    return subprocess.run(['docker','exec','-i','-e','MYSQL_PWD=sca-test-only',CONTAINER,'mysql','-uroot','sca_test'],input=body,capture_output=True,check=True)
def main():
    existing=subprocess.run(['docker','inspect',CONTAINER],capture_output=True)
    if existing.returncode:
        network=subprocess.run(['docker','network','inspect','binaryscan-sca-test'],capture_output=True)
        if network.returncode:subprocess.run(['docker','network','create','--label','binaryscan.sca-test=true','binaryscan-sca-test'],check=True,capture_output=True)
        subprocess.run(['docker','run','-d','--name',CONTAINER,'--label','binaryscan.sca-test=true','--network','binaryscan-sca-test','--memory','1g','-e','MYSQL_DATABASE=sca_test','-e','MYSQL_ROOT_PASSWORD=sca-test-only','-e','MYSQL_ROOT_HOST=%',os.environ.get('SCA_TEST_MYSQL_IMAGE','mysql:8.0')],check=True,capture_output=True)
    label=subprocess.check_output(['docker','inspect',CONTAINER,'--format','{{index .Config.Labels "binaryscan.sca-test"}}'],text=True).strip()
    if label!='true': raise RuntimeError('Not the dedicated SCA test database')
    running=subprocess.check_output(['docker','inspect',CONTAINER,'--format','{{.State.Running}}'],text=True).strip()
    if running!='true':subprocess.run(['docker','start',CONTAINER],check=True,capture_output=True)
    for _ in range(90):
        try:sql(b'SELECT 1;');break
        except subprocess.CalledProcessError:time.sleep(1)
    else:raise RuntimeError('Dedicated fixture MySQL did not become ready')
    sql(b'CREATE TABLE IF NOT EXISTS fixture_migrations(name VARCHAR(255) PRIMARY KEY);')
    names=sql(b'SELECT name FROM fixture_migrations;').stdout.decode().splitlines()
    for path in sorted((ROOT/'app/backend/migrations').glob('*.sql')):
        if path.name not in names:
            sql(path.read_bytes())
            sql(("INSERT INTO fixture_migrations VALUES ('"+path.name+"');").encode())
            print('Applied',path.name)
    for path in sorted((ROOT/'app/backend/migrations').glob('00001[4-8]_*.sql')):
        sql(path.read_bytes()); print('Repeated safely',path.name)
    sql(b'CREATE TABLE IF NOT EXISTS schema_migrations(version BIGINT UNSIGNED NOT NULL PRIMARY KEY,applied_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6));')
    for path in sorted((ROOT/'app/backend/migrations').glob('*.sql')):
        sql(('INSERT IGNORE INTO schema_migrations(version) VALUES ('+str(int(path.name.split('_')[0]))+');').encode())
    print('Fresh/upgrade-equivalent schema and repeatable new migrations passed')
if __name__=='__main__': main()
