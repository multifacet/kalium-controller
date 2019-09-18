def hash_djb2(s):                                                                                                                                
    hash = 5381
    for x in s:
        hash = (( hash << 5) + hash) + ord(x)
    return hash & 0xFFFFFFFF

t = [None] * 4
t[0] = "test0" + "GETE" + "cs.wisc.edu" + "POST"
t[1] = "test0" + "SEND" + "www.wisc.edu" + "GET"
t[2] = "test0" + "SEND" + "www.google.com" + "GET"
t[3] = "test0" + "SEND" + "www.facebook.com" + "GET"

for k in t:
	print hash_djb2(k)