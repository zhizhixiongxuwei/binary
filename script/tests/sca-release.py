"""Build all runtime images from the current source and assemble an isolated offline release."""
import hashlib, importlib.util, json, shutil, subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('binaryscan_build',ROOT/'script/lib/build.py')
build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)

def source_files():
    files=subprocess.check_output(['git','-C',str(ROOT),'ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\x00')
    records=[]
    for name in sorted(set(files)):
        if name and (name.startswith(('app/','checkers/','deploy/')) or name=='docker-compose.yml') and (ROOT/name).is_file():
            records.append(build.checksum(ROOT/name)+'  '+name+'\n')
    return ''.join(records)

def copy_review_material(output):
    docs=output/'docs';docs.mkdir(exist_ok=True)
    names=['java-impact-v1.md','requirements-sbom-java-vulnerability-analysis.md','implementation-plan-sbom-java-vulnerability-analysis.md']
    for name in names:shutil.copy2(ROOT/'docs'/name,docs/name)
    (docs/'sca-implementation-progress.md').write_text((ROOT/'docs/sca-implementation-progress.md').read_text(encoding='utf-8').replace('../app/backend/api/sca-v1.yaml','sca-v1.yaml'),encoding='utf-8')
    shutil.copy2(ROOT/'app/backend/api/sca-v1.yaml',docs/'sca-v1.yaml')
    text=(ROOT/'docs/sca-implementation-progress.md').read_text(encoding='utf-8')
    text=text.replace('../app/backend/api/sca-v1.yaml','docs/sca-v1.yaml')
    for name in names:text=text.replace(']('+name+')','](docs/'+name+')')
    (output/'SCA-IMPLEMENTATION.md').write_text(text,encoding='utf-8')
    evidence=output/'evidence';evidence.mkdir(exist_ok=True)
    for name in ['acceptance.json','acceptance-mysql9.json','ui-acceptance.jpg']:
        if (ROOT/'.cache/sca'/name).is_file():shutil.copy2(ROOT/'.cache/sca'/name,evidence/name)
    fixtures=ROOT/'test-fixtures/sca';manifest=fixtures/'manifest.json'
    if manifest.exists():
        target=output/'fixtures/sca';target.mkdir(parents=True,exist_ok=True)
        shutil.copy2(manifest,target/'manifest.json')
        for name,expected in json.loads(manifest.read_text(encoding='utf-8')).items():
            path=(fixtures/name).resolve()
            if not path.is_relative_to(fixtures.resolve()) or build.checksum(path)!=expected:raise RuntimeError('Fixture provenance mismatch: '+name)
            destination=target/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,destination)

def main():
    stage=ROOT/'.cache/sca/delivery-source'
    if (stage/'release').exists():raise RuntimeError('Preserve the existing SCA release before rebuilding')
    config=build.load_env(ROOT/'.env')
    for key in build.IMAGE_KEYS:
        if key!='MYSQL_IMAGE':config[key]=config[key].rsplit(':',1)[0]+':sca-20261117'
    config['BINARY_VERSION']='sca-20261117'
    before=source_files()
    build.build_images(ROOT,{**config,**build.load_env(ROOT/'deploy/docker/images.lock.env')})
    if before!=source_files():raise RuntimeError('Source inputs changed during image build; rebuild the final source snapshot')
    source=build.source_state(ROOT,False)
    stage.mkdir(parents=True,exist_ok=True)
    shutil.copy2(ROOT/'docker-compose.yml',stage/'docker-compose.yml')
    (stage/'.env').write_text(''.join(k+"='"+v+"'\n" for k,v in config.items()),encoding='utf-8')
    common=stage/'deploy/delivery/common';common.mkdir(parents=True,exist_ok=True)
    for name in build.TEMPLATES:shutil.copy2(ROOT/'deploy/delivery/common'/name,common/name)
    output=build.build_bundle(stage,'release',True)
    manifest=output/'manifests/images.json';data=json.loads(manifest.read_text(encoding='utf-8'));data['source']=source
    data['source']['input']='All application/worker/checker images built from the current working tree; MySQL uses the locked official image'
    data['source']['sourceTreeDigest']=hashlib.sha256(before.encode()).hexdigest()
    manifest.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    copy_review_material(output)
    (output/'manifests/source-files.sha256').write_text(before,encoding='utf-8')
    build.write_manifest(output)
    print('SCA offline release:',output)

if __name__=='__main__':main()
