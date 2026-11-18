"""Reproducible SBOM and bytecode fixtures; never executes sample applications."""
from pathlib import Path
import hashlib, json, subprocess, urllib.request, zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'test-fixtures' / 'sca'

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    libs = OUT / 'libs'; libs.mkdir(exist_ok=True)
    artifacts = {'commons-text-1.9.jar': 'org/apache/commons/commons-text/1.9/commons-text-1.9.jar',
                 'commons-lang3-3.11.jar': 'org/apache/commons/commons-lang3/3.11/commons-lang3-3.11.jar'}
    for name, path in artifacts.items():
        destination = libs / name
        if not destination.exists():
            with urllib.request.urlopen('https://repo.maven.apache.org/maven2/' + path, timeout=60) as r:
                destination.write_bytes(r.read())
        expected={'commons-text-1.9.jar':'0812f284ac5dd0d617461d9a2ab6ac6811137f25122dfffd4788a4871e732d00','commons-lang3-3.11.jar':'4ee380259c068d1dbe9e84ab52186f2acd65de067ec09beff731fca1697fdb16'}
        if hashlib.sha256(destination.read_bytes()).hexdigest()!=expected[name]:raise ValueError('Unexpected Maven fixture digest: '+name)
    for local,remote in [('spdx-2.3.1-official.json','SPDXJSONExample-v2.3.spdx.json'),('spdx-2.3.1-official.spdx','SPDXTagExample-v2.3.spdx')]:
        target=OUT/local
        if not target.exists():
            with urllib.request.urlopen('https://raw.githubusercontent.com/spdx/spdx-spec/v2.3.1/examples/'+remote,timeout=60) as r:target.write_bytes(r.read())
    component = {'type':'library','bom-ref':'text','group':'org.apache.commons','name':'commons-text',
                 'version':'1.9','purl':'pkg:maven/org.apache.commons/commons-text@1.9'}
    for v in ['1.4','1.5','1.6']:
        (OUT / f'cyclonedx-{v}.json').write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':v,
            'version':1,'components':[component]}), encoding='utf-8')
        (OUT / f'cyclonedx-{v}.xml').write_text(f'''<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/{v}" version="1"><components><component type="library" bom-ref="text"><group>org.apache.commons</group><name>commons-text</name><version>1.9</version><purl>pkg:maven/org.apache.commons/commons-text@1.9</purl></component></components></bom>''',encoding='utf-8')
    spdx = {'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT','name':'sca-fixture',
        'documentNamespace':'https://binaryscan.local/fixtures/sca/1',
        'creationInfo':{'created':'2026-11-17T00:00:00Z','creators':['Tool: BinaryScan-fixture']},
        'packages':[{'SPDXID':'SPDXRef-text','name':'commons-text','versionInfo':'1.9','downloadLocation':'NOASSERTION',
            'filesAnalyzed':False,'externalRefs':[{'referenceCategory':'PACKAGE-MANAGER','referenceType':'purl',
            'referenceLocator':component['purl']}]}]}
    (OUT/'spdx.json').write_text(json.dumps(spdx),encoding='utf-8')
    (OUT/'spdx.spdx').write_text('''SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: sca-fixture
DocumentNamespace: https://binaryscan.local/fixtures/sca/1
Creator: Tool: BinaryScan-fixture
Created: 2026-11-17T00:00:00Z
PackageName: commons-text
SPDXID: SPDXRef-text
PackageVersion: 1.9
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
ExternalRef: PACKAGE-MANAGER purl pkg:maven/org.apache.commons/commons-text@1.9
''',encoding='utf-8')
    (OUT/'swid.xml').write_text('''<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="commons-text" tagId="pkg:maven/org.apache.commons/commons-text@1.9" version="1.9" versionScheme="multipartnumeric"><Entity name="Apache" regid="apache.org" role="softwareCreator tagCreator"/></SoftwareIdentity>''',encoding='utf-8')
    (OUT/'swid-app.xml').write_text('''<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="demo" tagId="binaryscan:demo:1" version="1"><Entity name="Fixture" regid="binaryscan.local" role="tagCreator"/><Link rel="component" href="swid.xml"/></SoftwareIdentity>''',encoding='utf-8')
    (OUT/'log4j.json').write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':[{'type':'library','bom-ref':'log4j','name':'log4j-core','group':'org.apache.logging.log4j','version':'2.14.1','purl':'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'}]}),encoding='utf-8')
    source = OUT/'src'; source.mkdir(exist_ok=True)
    sources = {'Reachable': 'public static void main(String[] a) { org.apache.commons.text.StringSubstitutor.createInterpolator().replace(a[0]); }',
        'Unreachable': 'public static void main(String[] a) {} private static void unused(String s) { org.apache.commons.text.StringSubstitutor.createInterpolator().replace(s); }',
        'Reflective': 'public static void main(String[] a) throws Exception { Class.forName(a[0]).getDeclaredMethods(); }'}
    for name, body in sources.items():
        (source/(name+'.java')).write_text('public class '+name+' { '+body+' }',encoding='utf-8')
    subprocess.run(['docker','run','--rm','--network','none','-v',str(ROOT)+':/src','-w','/src/test-fixtures/sca',
        'maven:3.9.11-eclipse-temurin-21','javac','--release','8','-cp','libs/*','-d','classes',
        *['src/'+name+'.java' for name in sources]],check=True)
    for name in sources:
        for layout, app, dep in [('plain','','lib/'),('boot','BOOT-INF/classes/','BOOT-INF/lib/'),('war','WEB-INF/classes/','WEB-INF/lib/')]:
            extension = 'war' if layout=='war' else 'jar'
            with zipfile.ZipFile(OUT/f'{name.lower()}-{layout}.{extension}','w',zipfile.ZIP_DEFLATED) as z:
                def entry(path,data):
                    info=zipfile.ZipInfo(path,(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,data)
                entry(app+name+'.class',(OUT/'classes'/(name+'.class')).read_bytes())
                entry('META-INF/MANIFEST.MF',('Manifest-Version: 1.0\nMain-Class: '+name+'\n\n').encode())
                for jar in sorted(libs.glob('*.jar')): entry(dep+jar.name,jar.read_bytes())
    inputs=[*OUT.glob('*.jar'),*OUT.glob('*.war'),*OUT.glob('cyclonedx-*'),*OUT.glob('spdx*'),OUT/'swid.xml',OUT/'swid-app.xml',OUT/'log4j.json',*libs.glob('*.jar')]
    manifest = {p.relative_to(OUT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(inputs)}
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({'directory':str(OUT),'sha256':manifest},indent=2))

if __name__ == '__main__': main()
