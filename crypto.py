import requests
try: input = raw_input
except NameError: pass

# Global values
base = "http://crypto.praetorian.com/{}"
email = "saltbourne@gmail.com"
auth_token = None

# Used for authentication
def token(email):
	global auth_token
	if not auth_token:
		url = base.format("api-token-auth/")
		resp = requests.post(url, data={"email":email})
		auth_token = {"Authorization":"JWT " + resp.json()['token']}
		resp.close()
	return auth_token

# Fetch the challenge and hint for level n
def fetch(n):
	url = base.format("challenge/{}/".format(n))
	resp = requests.get(url, headers=token(email))
	resp.close()
	if resp.status_code != 200:
		raise Exception(resp.json()['detail'])
	return resp.json()

# Submit a guess for level n
def solve(n, guess):
	url = base.format("challenge/{}/".format(n))
	data = {"guess": guess}
	resp = requests.post(url, headers=token(email), data=data)
	resp.close()
	if resp.status_code != 200:
		raise Exception(resp.json()['detail'])
	return resp.json()

def rot3_decode(guess):
	s = ""
	for i in guess:
		rot = ord(i) + 3
		if i.isalpha():
			if (i.isupper() and rot < ord('A')) or (i.islower() and rot < ord('a')):
				rot += 26
			elif (i.isupper() and rot > ord('Z')) or (i.islower() and rot > ord('z')):
				rot -= 26
			s += chr(rot)
		else:
			s += chr(i)
	return s

# Fetch level 0
level = 1
hashes = {}
data = fetch(level)

# Level 0 is a freebie and gives you the password
guess = data['challenge']
decoded = rot3_decode(guess)
h = solve(level, decoded)

# If we obtained a hash add it to the dict
if 'hash' in h: hashes[level] = h['hash']


# Display all current hash
for k,v in hashes.items():
	print("Level {}: {}".format(k, v))
