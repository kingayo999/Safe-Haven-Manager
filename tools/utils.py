"""Small helper scripts for local testing: fetch root and try-login.

Usage:
  python -m tools.utils fetch
  python -m tools.utils login
"""
import sys


def fetch_root():
    import urllib.request

    try:
        r = urllib.request.urlopen('http://127.0.0.1:5000', timeout=5)
        data = r.read()
        print('STATUS', r.status)
        print(data.decode('utf-8')[:2000])
    except Exception as e:
        print('ERROR', type(e).__name__, e)
        sys.exit(1)


def try_login():
    try:
        import requests
    except Exception:
        print('requests required for try_login')
        sys.exit(1)
    s = requests.Session()
    print('POST /login')
    r = s.post('http://127.0.0.1:5000/login', data={'username': 'demo', 'password': 'demo'}, allow_redirects=False)
    print('login status', r.status_code, r.headers.get('Location'))
    print('GET /home')
    r2 = s.get('http://127.0.0.1:5000/home')
    print('home status', r2.status_code)
    print(r2.text[:2000])


def main():
    if len(sys.argv) < 2:
        print('Usage: python -m tools.utils [fetch|login]')
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'fetch':
        fetch_root()
    elif cmd == 'login':
        try_login()
    else:
        print('Unknown command')


if __name__ == '__main__':
    main()
