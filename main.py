import requests
import sys
import hashlib


def get_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + query
    response = requests.get(url)
    if response.status_code != 200:
        return RuntimeError(f'Error fetching: {response.status_code}, check the api and try again.')
    return response


def password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def hashed_password_check(password):
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_five_char, rest_char = get_data(hashed_password[:5]), get_data(hashed_password[5:])
    return password_leak_count(first_five_char, rest_char)


def leak_check(args):
    for password in args:
        count = hashed_password_check(password)
        if count:
            print(f'{password} was found {count} times.')
        else:
            print(f'{password} NOT found in leaked database.')
    return 'Done!'


if __name__ == '__main__':
   sys.exit(leak_check(sys.argv[1:]))


