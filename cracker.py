from hashlib import md5, sha256
f_alg = {"MD5": md5, "SHA256": sha256}

def compute_digest(realm, username, password, nonce, uri, algorithm):
    f = f_alg[algorithm]
    a1 = f(f"{username}:{realm}:{password}".encode()).hexdigest()
    a2 = f(f"GET:{uri}".encode()).hexdigest()

    return f(f"{a1}:{nonce}:{a2}".encode()).hexdigest()

if __name__ == "__main__":
    header = 'Authorization: Digest username="ericamiller",realm="pamela12@example.org", nonce="ba4c8a026b9b7eef872483089d3738ea6f827e898da8d0992effb2b5122ddf73", uri="/auth", qop=auth, response="1156aef0b43e273fc6f7d1141b6da55f3141bde8f0911c901a288ec18a043c7e", algorithm=SHA256'

    username = header.split('username="')[1].split('"')[0]
    realm = header.split('realm="')[1].split('"')[0]
    nonce = header.split('nonce="')[1].split('"')[0]
    response = header.split('response="')[1].split('"')[0]
    uri = header.split('uri="')[1].split('"')[0]
    algorithm = header.split('algorithm=')[1]

    print(username, realm, nonce, response, uri, algorithm)

    with open("top10k.txt", "r") as f:
        passwd = f.read().split("\n")

    for p in passwd:
        if compute_digest(realm, username, p, nonce, uri, algorithm) == response:
            print(f"Password = {p}")
