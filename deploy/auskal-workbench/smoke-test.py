import json,urllib.request,urllib.error
BASE='https://dev.auskal.tech'
with urllib.request.urlopen(BASE+'/',timeout=15) as response:
    assert response.status==200 and response.url.endswith('/login')
    assert 'Welcome back.' in response.read().decode()
    assert not response.headers.get('WWW-Authenticate')
print('PASS: HTTPS redirects to normal sign-in form')
for route in ['/api/status','/api/jobs']:
    try:
        urllib.request.urlopen(BASE+route,timeout=15)
        raise AssertionError('Unauthenticated API access was accepted')
    except urllib.error.HTTPError as error:
        assert error.code==401
        assert not error.headers.get('WWW-Authenticate')
        assert 'error' in json.load(error)
print('PASS: private API requires a session without browser pop-up authentication')
for origin,expected in [('https://untrusted.example',403),('https://dev.auskal.tech',401)]:
    request=urllib.request.Request(BASE+'/api/login',data=json.dumps({'username':'__invalid_test_user__','password':'invalid-test-input'}).encode(),headers={'Content-Type':'application/json','Origin':origin,'X-REA-Request':'workbench'})
    try:
        urllib.request.urlopen(request,timeout=15)
        raise AssertionError('Invalid sign-in was accepted')
    except urllib.error.HTTPError as error:
        assert error.code==expected,(error.code,error.read())
        assert not error.headers.get('WWW-Authenticate')
print('PASS: invalid credentials and cross-origin sign-in rejected')
