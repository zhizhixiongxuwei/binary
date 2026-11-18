"""Fetch reviewed upstream schemas at build-preparation time (never at scan time)."""
from pathlib import Path
import hashlib, json, urllib.request

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'app/backend/internal/sbom/schemas'
SOURCES = {
    'spdx-2.3.json':'https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json',
    'swid.xsd':'https://standards.iso.org/iso/19770/-2/2015-current/schema.xsd',
    'xmldsig-core-schema.xsd':'https://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd',
    'xml.xsd':'https://www.w3.org/2001/xml.xsd',
}
for v in ['1.4','1.5','1.6']:
    for ext in ['schema.json','xsd']:
        SOURCES[f'bom-{v}.{ext}']=f'https://raw.githubusercontent.com/CycloneDX/specification/{v}/schema/bom-{v}.{ext}'
for name in ['spdx.schema.json','jsf-0.82.schema.json','spdx.xsd']:
    SOURCES[name]='https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/'+name

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    manifest=[]
    for name,url in SOURCES.items():
        with urllib.request.urlopen(url,timeout=60) as r: raw=r.read()
        body=raw
        if name.endswith('.xsd'):
            # Namespace declarations are identities; only schemaLocation is localized.
            body=raw.replace(b'schemaLocation="http://cyclonedx.org/schema/spdx"',b'schemaLocation="spdx.xsd"')
            for remote in [b'http://www.w3.org/2001/xml.xsd',b'https://www.w3.org/2001/xml.xsd']:
                body=body.replace(b'schemaLocation="'+remote+b'"',b'schemaLocation="xml.xsd"')
            body=body.replace(b'schemaLocation="http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd"',b'schemaLocation="xmldsig-core-schema.xsd"')
        if name=='swid.xsd' and b'targetNamespace="http://standards.iso.org/iso/19770/-2/2015/schema.xsd"' not in body:
            raise ValueError('SWID upstream does not identify the reviewed 2015 namespace')
        (OUT/name).write_bytes(body)
        manifest.append({'file':name,'url':url,'upstreamSha256':hashlib.sha256(raw).hexdigest(),
                         'sha256':hashlib.sha256(body).hexdigest()})
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print('Prepared',len(manifest),'offline schemas')

if __name__=='__main__': main()
