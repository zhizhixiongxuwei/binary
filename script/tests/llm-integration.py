#!/usr/bin/env python3
"""Real App/MySQL/SSE integration in disposable, labelled Docker resources.

Usage: python script/tests/llm-integration.py {setup|check|cleanup}
All images must already exist. No existing account, volume or service is changed.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / '.cache/llm-integration'
STATE = ROOT / 'resources.json'
LABEL = 'com.binaryscan.llm-integration'
BASE = 'http://127.0.0.1:18082'
UPSTREAM = 'http://127.0.0.1:18083'
ADMIN = 'llm-test-admin'
PASSWORD = 'OnlyFixture_2026!'


def docker(args, *, payload=None, environment=None, check=True):
    result = subprocess.run(['docker', *args], input=payload, capture_output=True, env=environment)
    if check and result.returncode:
        # Keep credentials and full command arguments out of diagnostic output.
        raise RuntimeError('Docker operation failed: ' + result.stderr.decode('utf-8', 'replace')[:1000])
    return result


def save(state):
    ROOT.mkdir(parents=True, exist_ok=True)
    temporary = STATE.with_suffix('.new')
    temporary.write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
    temporary.chmod(0o600)
    temporary.replace(STATE)


def load():
    state = json.loads(STATE.read_text(encoding='utf-8'))
    if state.get('workspace') != str(REPO) or not re.fullmatch(r'[0-9a-f]{24}', state.get('owner', '')):
        raise RuntimeError('Invalid integration ownership record')
    expected = 'binary-llm-check-' + state['owner'][:10]
    if state.get('prefix') != expected or any(state[key] != expected + suffix for key, suffix in [('app', '-app'), ('mysql', '-mysql'), ('provider', '-provider'), ('network', '-net')]):
        raise RuntimeError('Resource names do not match integration owner')
    if state.get('storage') != str(ROOT / expected / 'storage'):
        raise RuntimeError('Storage path does not match integration owner')
    return state


def live_state():
    state = load()
    if state.get('cleaned') or not state.get('ready'):
        raise RuntimeError('Integration setup must be ready before check')
    for kind in ('app', 'provider', 'mysql', 'network'):
        args = ['network', 'inspect'] if kind == 'network' else ['inspect']
        metadata = json.loads(docker([*args, state[kind]]).stdout)[0]
        labels = metadata.get('Labels', {}) if kind == 'network' else metadata['Config'].get('Labels', {})
        if labels.get(LABEL) != state['owner']:
            raise RuntimeError('Refusing to check resources not owned by this integration run')
        if kind in ('app', 'provider'):
            port = '18082' if kind == 'app' else '18083'
            bindings = metadata.get('NetworkSettings', {}).get('Ports', {}).get('8080/tcp') or []
            if not any(item['HostIp'] == '127.0.0.1' and item['HostPort'] == port for item in bindings):
                raise RuntimeError('Fixture endpoint does not match its owned container')
    return state


def sql(statement, state):
    result = docker(['exec', '-i', state['mysql'], 'sh', '-c',
        'IFS= read -r MYSQL_PWD; export MYSQL_PWD; exec mysql -uroot --batch --skip-column-names --default-character-set=utf8mb4 llm_fixture'],
        payload=(state['rootPassword'] + '\n' + statement + '\n').encode('utf-8'))
    return result.stdout.decode('utf-8', 'replace').strip()


def client():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def request(opener, path, *, method='GET', data=None, csrf=None, raw=False, base=BASE):
    headers = {'Accept': 'text/event-stream' if raw else 'application/json'}
    if csrf: headers['X-CSRF-Token'] = csrf
    if data is not None: headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(base + path, headers=headers, method=method,
        data=None if data is None else json.dumps(data).encode())
    try: response = opener.open(req, timeout=20)
    except urllib.error.HTTPError as error: response = error
    if raw and response.status == 200: return response
    with response:
        body = response.read()
        return response.status, json.loads(body) if body else None


def login(username=ADMIN, password=PASSWORD):
    opener = client()
    status, body = request(opener, '/api/v1/auth/login', method='POST', data={'username': username, 'password': password})
    assert status == 200, ('login', status, body)
    return opener, body['user']['csrfToken']


def wait_ready():
    opener = client()
    for _ in range(90):
        try:
            if request(opener, '/readyz')[0] == 200: return
        except (OSError, urllib.error.URLError): pass
        time.sleep(1)
    raise RuntimeError('Isolated App did not become ready')


def wait_provider_idle(*, cancelled_after=None):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        stats = request(client(), '/stats', base=UPSTREAM)[1]
        if stats['active'] == 0 and (cancelled_after is None or stats['cancelled'] > cancelled_after):
            return
        time.sleep(0.1)
    raise AssertionError('Provider did not observe cancellation and release its active request')


def setup():
    if STATE.exists() and not json.loads(STATE.read_text()).get('cleaned'):
        raise RuntimeError('Integration resources already recorded; check or cleanup first')
    for port in (18082, 18083):
        with socket.socket() as probe: probe.bind(('127.0.0.1', port))
    owner = secrets.token_hex(12)
    prefix = 'binary-llm-check-' + owner[:10]
    state = {'workspace': str(REPO), 'owner': owner, 'prefix': prefix,
        'app': prefix + '-app', 'mysql': prefix + '-mysql', 'provider': prefix + '-provider', 'network': prefix + '-net',
        'storage': str(ROOT / prefix / 'storage'),
        'rootPassword': secrets.token_hex(24), 'dbPassword': secrets.token_hex(24), 'created': [], 'cleaned': False}
    save(state)
    docker(['network', 'create', '--label', LABEL + '=' + owner, state['network']])
    state['created'].append('network'); save(state)
    env = {**os.environ, 'MYSQL_ROOT_PASSWORD': state['rootPassword'], 'MYSQL_DATABASE': 'llm_fixture', 'MYSQL_USER': 'llm_fixture', 'MYSQL_PASSWORD': state['dbPassword']}
    docker(['run', '-d', '--pull=never', '--name', state['mysql'], '--label', LABEL + '=' + owner,
        '--network', state['network'], '--tmpfs', '/var/lib/mysql:rw,size=1g,mode=0700',
        '-e', 'MYSQL_ROOT_PASSWORD', '-e', 'MYSQL_DATABASE', '-e', 'MYSQL_USER', '-e', 'MYSQL_PASSWORD', 'mysql:9.7.1'], environment=env)
    state['created'].append('mysql'); save(state)
    for _ in range(90):
        try:
            if sql('SELECT 1;', state) == '1': break
        except RuntimeError: pass
        time.sleep(1)
    else: raise RuntimeError('Isolated MySQL did not become ready')
    storage = Path(state['storage'])
    storage.mkdir(parents=True, exist_ok=False)
    for directory in ('blobs', 'uploads', 'projects/native/fixture', 'projects/native/fixture-secondary'):
        (storage / directory).mkdir(parents=True, exist_ok=True)
    source_a = 'int sum_values(const int *values, int count) {\n    int result = 0;\n    for (int i = 0; i < count; i++) {\n        result += values[i];\n    }\n    return result;\n}\n' + ''.join(f'// source A context line {index}\n' for index in range(8, 260))
    source_b = 'int multiply(int left, int right) {\n    return left * right;\n}\n' + ''.join(f'// source B context line {index}\n' for index in range(4, 180))
    protocol_source = 'int protocol_version(const unsigned char *packet, int length) {\n    if (!packet || length < 1) return -1;\n    return packet[0] & 15;\n}\n'
    checksum_source = 'unsigned int checksum_bytes(const unsigned char *data, int length) {\n    unsigned int total = 0;\n    for (int index = 0; index < length; index++) total += data[index];\n    return total & 255;\n}\n'
    checksum_test_source = 'int checksum_fixture_test(void) {\n    /* This file intentionally shares a basename with src/util/checksum.c. */\n    const unsigned char sample[] = {1, 2, 3};\n    return checksum_bytes(sample, 3) == 6;\n}\n'
    secondary_sum_source = 'int secondary_sum(const int *values, int count) {\n    /* A different source project intentionally publishes the same sum.c name. */\n    int total = 100;\n    for (int index = 0; index < count; index++) total += values[index];\n    return total;\n}\n' + ''.join(f'// secondary project context line {index}\n' for index in range(7, 120))

    def write_sources(state_key, storage_key, pairs):
        state[state_key] = []
        for filename, source in pairs:
            target = storage / 'projects/native' / storage_key / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding='utf-8', newline='\n')
            state[state_key].append({'id': str(uuid.uuid4()), 'filename': filename, 'sha256': hashlib.sha256(source.encode()).hexdigest(), 'size': len(source.encode()), 'lines': len(source.split('\n'))})

    # Preserve the first two identities/order: check() depends on sum and multiply.
    write_sources('files', 'fixture', [('sum.c', source_a), ('multiply.c', source_b), ('src/net/protocol.c', protocol_source), ('src/util/checksum.c', checksum_source), ('tests/checksum.c', checksum_test_source)])
    write_sources('secondFiles', 'fixture-secondary', [('sum.c', secondary_sum_source)])
    state.update({key: str(uuid.uuid4()) for key in ('taskId', 'projectId', 'blobId', 'nodeId', 'runId', 'secondProjectId', 'secondNodeId', 'secondRunId')}); save(state)
    python_image = 'public.ecr.aws/docker/library/python:3.13.15-slim-bookworm'
    docker(['run', '-d', '--pull=never', '--name', state['provider'], '--label', LABEL + '=' + owner,
        '--network', state['network'], '--network-alias', 'provider', '-p', '127.0.0.1:18083:8080',
        '-v', str(REPO / 'script/tests/llm-provider-fixture.py') + ':/provider.py:ro', python_image, 'python', '-u', '/provider.py'])
    state['created'].append('provider'); save(state)
    env = {**os.environ, 'BINARY_ROLE': 'app', 'BINARY_VERSION': 'llm-integration', 'BINARY_LISTEN_ADDR': ':8080',
        'BINARY_DB_HOST': state['mysql'], 'BINARY_DB_PORT': '3306', 'BINARY_DB_NAME': 'llm_fixture', 'BINARY_DB_USER': 'llm_fixture',
        'BINARY_DB_PASSWORD': state['dbPassword'], 'BINARY_PUBLIC_BASE_URL': BASE, 'BINARY_ALLOWED_ORIGINS': BASE,
        'BINARY_INITIAL_ADMIN_USERNAME': ADMIN, 'BINARY_INITIAL_ADMIN_PASSWORD': PASSWORD, 'BINARY_STORAGE_ROOT': '/data/storage'}
    args = ['run', '-d', '--pull=never', '--name', state['app'], '--label', LABEL + '=' + owner,
        '--network', state['network'], '-p', '127.0.0.1:18082:8080', '--read-only', '--user', '10001:10001',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp:rw,size=128m,mode=1777',
        '-v', str(storage) + ':/data/storage']
    for key in env:
        if key.startswith('BINARY_'): args.extend(['-e', key])
    docker(args + ['binaryscan/app:0.1.0-dev'], environment=env)
    state['created'].append('app'); save(state)
    wait_ready()
    admin_id = sql("SELECT id FROM users WHERE username='llm-test-admin';", state)
    statements = [
        f"INSERT INTO blobs(id,sha256,size_bytes,storage_key) VALUES('{state['blobId']}',UNHEX(SHA2('llm-fixture',256)),64,'fixture.bin');",
        f"INSERT INTO tasks(id,created_by,blob_id,display_name,status,detected_format) VALUES('{state['taskId']}',{admin_id},'{state['blobId']}','LLM source reader fixture','ready','elf64');",
        f"INSERT INTO file_nodes(id,task_id,blob_id,logical_path,node_kind,detected_format,size_bytes) VALUES('{state['nodeId']}','{state['taskId']}','{state['blobId']}','fixture.bin','file','elf64',64);",
        f"INSERT INTO runs(id,kind,status,task_id,subject_type,subject_id,created_by,idempotency_key,result_quality,started_at,completed_at,published_at) VALUES('{state['runId']}','native_decompile','complete','{state['taskId']}','file_node','{state['nodeId']}',{admin_id},'llm-fixture','source',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6));",
        f"INSERT INTO source_projects(id,task_id,file_node_id,run_id,source_kind,language,result_quality,root_storage_key,file_count,size_bytes) VALUES('{state['projectId']}','{state['taskId']}','{state['nodeId']}','{state['runId']}','native','c','source','fixture',{len(state['files'])},{sum(item['size'] for item in state['files'])});",
        f"INSERT INTO file_nodes(id,task_id,blob_id,logical_path,node_kind,detected_format,size_bytes) VALUES('{state['secondNodeId']}','{state['taskId']}','{state['blobId']}','secondary.bin','file','elf64',64);",
        f"INSERT INTO runs(id,kind,status,task_id,subject_type,subject_id,created_by,idempotency_key,result_quality,started_at,completed_at,published_at) VALUES('{state['secondRunId']}','native_decompile','complete','{state['taskId']}','file_node','{state['secondNodeId']}',{admin_id},'llm-fixture-secondary','source',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6));",
        f"INSERT INTO source_projects(id,task_id,file_node_id,run_id,source_kind,language,result_quality,root_storage_key,file_count,size_bytes) VALUES('{state['secondProjectId']}','{state['taskId']}','{state['secondNodeId']}','{state['secondRunId']}','native','c','source','fixture-secondary',{len(state['secondFiles'])},{sum(item['size'] for item in state['secondFiles'])});",
    ]
    for item in state['files']:
        statements.append(f"INSERT INTO source_files(id,source_project_id,logical_path,language,sha256,size_bytes,line_count) VALUES('{item['id']}','{state['projectId']}','{item['filename']}','c',UNHEX('{item['sha256']}'),{item['size']},{item['lines']});")
    for item in state['secondFiles']:
        statements.append(f"INSERT INTO source_files(id,source_project_id,logical_path,language,sha256,size_bytes,line_count) VALUES('{item['id']}','{state['secondProjectId']}','{item['filename']}','c',UNHEX('{item['sha256']}'),{item['size']},{item['lines']});")
    sql('\n'.join(statements), state)
    state['ready'] = True; save(state)
    print(json.dumps({'ready': True, 'url': BASE, 'taskId': state['taskId'], 'projectId': state['projectId'], 'files': state['files'], 'secondProjectId': state['secondProjectId'], 'secondFiles': state['secondFiles']}))


def events(response):
    if isinstance(response, tuple): return response
    with response:
        frames = response.read().decode().replace('\r\n', '\n').strip().split('\n\n')
    result = []
    for frame in frames:
        event = 'message'; data = []
        for line in frame.splitlines():
            if line.startswith('event:'): event = line[6:].strip()
            if line.startswith('data:'): data.append(line[5:].strip())
        if data: result.append((event, json.loads('\n'.join(data))))
    return result


def check():
    state = live_state(); admin, csrf = login()
    request(client(), '/mode', method='POST', data={'mode': 'normal'}, base=UPSTREAM)
    file = state['files'][0]
    endpoint = f"/api/v1/tasks/{state['taskId']}/projects/{state['projectId']}/files/{file['id']}/explanations"
    assert request(admin, '/api/v1/llm/status')[0] == 200
    config = {'enabled': True, 'provider': 'openai-compatible', 'baseUrl': 'http://provider:8080/v1', 'model': 'fixture-code', 'apiKey': 'fixture-key', 'maxInputChars': 60000, 'timeoutSeconds': 10, 'maxConcurrent': 1, 'maxOutputTokens': 1024}
    status, saved = request(admin, '/api/v1/admin/llm/settings', method='PUT', data=config, csrf=csrf)
    assert status == 200 and saved['configured'] and 'fixture-key' not in json.dumps(saved), ('settings', status, saved)
    assert request(admin, '/api/v1/admin/llm/test', method='POST', csrf=csrf)[0] == 200
    base_input = {'scope': 'file', 'requestId': str(uuid.uuid4()), 'sourceSha256': file['sha256']}
    assert request(admin, endpoint, method='POST', data=base_input)[0] == 403
    response = events(request(admin, endpoint, method='POST', data=base_input, csrf=csrf, raw=True))
    assert isinstance(response, list) and any(kind == 'delta' for kind, _ in response) and response[-1][0] == 'done', ('stream', response)
    assert response[-1][1]['status'] == 'completed' and response[-1][1]['sourceSha256'] == file['sha256']
    before = request(client(), '/stats', base=UPSTREAM)[1]['calls']
    cached = events(request(admin, endpoint, method='POST', data={**base_input, 'requestId': str(uuid.uuid4())}, csrf=csrf, raw=True))
    assert isinstance(cached, list) and cached[-1][1]['cacheHit']
    assert request(client(), '/stats', base=UPSTREAM)[1]['calls'] == before
    assert request(admin, endpoint)[1]['items']
    selected = {**base_input, 'scope': 'selection', 'startLine': 1, 'endLine': 3, 'requestId': str(uuid.uuid4())}
    assert events(request(admin, endpoint, method='POST', data=selected, csrf=csrf, raw=True))[-1][0] == 'done'
    prompt = request(client(), '/stats', base=UPSTREAM)[1]['lastPrompt']
    assert 'L3:' in prompt and 'source A context line 259' not in prompt
    assert request(admin, endpoint, method='POST', data={**base_input, 'sourceSha256': '0' * 64}, csrf=csrf)[0] == 409
    status, _ = request(admin, '/api/v1/admin/users', method='POST', csrf=csrf, data={'username': 'llm-test-reader', 'password': PASSWORD, 'role': 'reader'})
    assert status in (201, 409), ('reader fixture creation', status)
    reader, reader_csrf = login('llm-test-reader')
    assert request(reader, endpoint)[0] == 200
    assert request(reader, endpoint, method='POST', data=base_input, csrf=reader_csrf)[0] == 403
    assert request(reader, '/api/v1/admin/llm/settings')[0] == 403
    print('PASS: settings, masked key, connection test, SSE, selection boundary, cache, history, SHA guard, CSRF and reader permissions')
    request(client(), '/mode', method='POST', data={'mode': 'rate'}, base=UPSTREAM)
    limited = events(request(admin, endpoint, method='POST', data={**base_input, 'requestId': str(uuid.uuid4()), 'regenerate': True}, csrf=csrf, raw=True))
    assert (isinstance(limited, tuple) and limited[0] == 429) or (isinstance(limited, list) and limited[-1][0] == 'error' and limited[-1][1]['code'] == 'llm_rate_limited'), ('rate', limited)
    request(client(), '/mode', method='POST', data={'mode': 'normal'}, base=UPSTREAM)
    print('PASS: upstream rate limit is reported without a false completion')
    # Limits are explicit; no silent truncation or unsolicited second request.
    assert request(admin, '/api/v1/admin/llm/settings', method='PUT', csrf=csrf, data={'maxInputChars': 256})[0] == 200
    assert request(admin, endpoint, method='POST', data={**base_input, 'requestId': str(uuid.uuid4()), 'regenerate': True}, csrf=csrf)[0] == 413
    assert request(admin, '/api/v1/admin/llm/settings', method='PUT', csrf=csrf, data={'maxInputChars': 60000})[0] == 200
    request(client(), '/mode', method='POST', data={'mode': 'slow'}, base=UPSTREAM)
    cancelled_before = request(client(), '/stats', base=UPSTREAM)[1]['cancelled']
    cancel_id = str(uuid.uuid4())
    pending = request(admin, endpoint, method='POST', data={**base_input, 'requestId': cancel_id, 'regenerate': True}, csrf=csrf, raw=True)
    assert not isinstance(pending, tuple)
    while True:
        line = pending.readline()
        if not line: raise AssertionError('Pending stream ended before its first delta')
        if line.startswith(b'event: delta'): break
    second_file = state['files'][1]
    second_endpoint = f"/api/v1/tasks/{state['taskId']}/projects/{state['projectId']}/files/{second_file['id']}/explanations"
    assert request(admin, second_endpoint, method='POST', data={'scope': 'file', 'requestId': str(uuid.uuid4())}, csrf=csrf)[0] == 429
    pending.close()
    for _ in range(40):
        matching = [item for item in request(admin, endpoint)[1]['items'] if item['id'] == cancel_id]
        if matching and matching[0]['status'] == 'cancelled': break
        time.sleep(0.25)
    else: raise AssertionError('Cancelled client stream was not saved as cancelled')
    # The App saves cancellation before TCP FIN necessarily reaches the provider.
    wait_provider_idle(cancelled_after=cancelled_before)
    print('PASS: input limit, concurrency cap, provider cancellation and partial history')
    request(client(), '/mode', method='POST', data={'mode': 'timeout'}, base=UPSTREAM)
    assert request(admin, '/api/v1/admin/llm/settings', method='PUT', csrf=csrf, data={'timeoutSeconds': 5})[0] == 200
    timed = events(request(admin, endpoint, method='POST', data={**base_input, 'requestId': str(uuid.uuid4()), 'regenerate': True}, csrf=csrf, raw=True))
    assert isinstance(timed, list) and timed[-1][0] == 'error' and 'timeout' in timed[-1][1]['code'], ('timeout', timed)
    wait_provider_idle()
    request(client(), '/mode', method='POST', data={'mode': 'normal'}, base=UPSTREAM)
    assert request(admin, '/api/v1/admin/llm/settings', method='PUT', csrf=csrf, data={'timeoutSeconds': 10})[0] == 200
    print('PASS: provider timeout becomes a stable stream error')
    changed_path = Path(state['storage']) / 'projects/native/fixture' / file['filename']
    changed_source = changed_path.read_text(encoding='utf-8') + '// changed source revision\n'
    changed_path.write_text(changed_source, encoding='utf-8', newline='\n')
    changed_hash = hashlib.sha256(changed_source.encode()).hexdigest()
    sql(f"UPDATE source_files SET sha256=UNHEX('{changed_hash}'),size_bytes={len(changed_source.encode())},line_count={len(changed_source.split(chr(10)))} WHERE id='{file['id']}';", state)
    assert any(item['stale'] for item in request(admin, endpoint)[1]['items'])
    file.update({'sha256': changed_hash, 'size': len(changed_source.encode()), 'lines': len(changed_source.split('\n'))})
    save(state)
    # Omitted keys preserve the saved credential, including after a process restart.
    saved_config = request(admin, '/api/v1/admin/llm/settings')[1]
    assert saved_config['configured']
    settings_file = Path(state['storage']) / '.settings/llm.json'
    assert settings_file.exists() and b'fixture-key' not in settings_file.read_bytes()
    docker(['restart', state['app']]); wait_ready()
    assert request(admin, '/api/v1/admin/llm/settings')[1]['configured']
    assert request(admin, '/api/v1/admin/llm/test', method='POST', csrf=csrf)[0] == 200
    print('PASS: stale source history and encrypted configuration survive restart')
    state['checked'] = True; save(state)


def cleanup():
    state = load()
    for kind in ('app', 'provider', 'mysql'):
        inspected = docker(['inspect', state[kind]], check=False)
        if inspected.returncode == 0:
            metadata = json.loads(inspected.stdout)[0]
            if metadata['Config'].get('Labels', {}).get(LABEL) != state['owner']:
                raise RuntimeError('Refusing to remove a container not owned by this integration run')
            docker(['rm', '-f', state[kind]])
    inspected = docker(['network', 'inspect', state['network']], check=False)
    if inspected.returncode == 0:
        if json.loads(inspected.stdout)[0].get('Labels', {}).get(LABEL) != state['owner']:
            raise RuntimeError('Refusing to remove an unowned network')
        docker(['network', 'rm', state['network']])
    state.pop('rootPassword', None); state.pop('dbPassword', None)
    state['cleaned'] = True; save(state)
    print('Owned integration containers and network removed; fixture files retained')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['setup', 'check', 'cleanup'])
    action = parser.parse_args().action
    globals()[action]()
