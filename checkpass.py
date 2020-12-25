import requests
import hashlib
import sys
import re

#here we sent request to the API 
def api_req(char):
	url = "https://api.pwnedpasswords.com/range/"+char
	response = requests.get(url)
	# if the status is not 200 we will raise an Error
	if response.status_code != 200:
		raise RuntimeError(f'Status: {response.status_code}, Please check again your API address')
	return response

#make a function to count if there a match tail from the response_hases
def count_leaked_password(response, tail_to_check):
	#we need to split the response which is list of all tail/rest of leaked password with match first five char of by ':' each line 
	tuple_hases = (line.split(':') for line in response.text.splitlines())
	for hash_pass, count in tuple_hases:
		if hash_pass == tail_to_check:
			return count 
	#after checking everything and there is no match we return 0		
	return 0

def have_been_pwned(password):
	hashed_pass = hashlib.sha1(password.encode('ascii')).hexdigest().upper()
	head,tail = hashed_pass[:5], hashed_pass[5:]
	response_hash = api_req(head)
	# it will return count of match tail  
	return count_leaked_password(response_hash, tail)

#this function will receive the password we want to check and count if it ever have been leaked 
def main(args):
	#loop through the password we give
    for number,password in enumerate(args):
        count = have_been_pwned(password)
        if count:
        	# if count isn't 0
            print(f'OHH NO {number} PASSWORD has been pwned {count} times')
        else:
            print(f'{number} PASSWORD NEVER BEEN PWNED !')
    return 'done!'


#we open a file where we store our password
with open('text.txt', mode='r') as text:
    arg = text.readlines()

string = ''.join([str(i) for i in arg])
strip = string.strip('\n')
args = re.split(r'\s', strip)

if __name__ == "__main__":
    sys.exit(main(args))

