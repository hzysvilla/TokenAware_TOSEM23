collect = {}
lastaddr = ''
lastflag = False
with open('abiresult', 'r') as f:
	for line in f:
		info = line[0:len(line)-1].split('#')
		if info[0] == 'addr':
			if lastflag == True:
				collect[lastaddr] = 1
				lastflag = False
			lastaddr = info[1]
			lastflag = True
		else:
			lastflag = False
f.close()
if lastflag == True:
	collect[lastaddr] = 1
with open('code/300select', 'r') as f:
	for line in f:
		info = line[0:len(line)-1].split('#')
		if info[0] in collect:
			collect[info[0]] = info[1]
f.close()
with open('code/29error', 'w') as f:
	for k,v in collect.items():
		f.write(str(k)+'#'+str(v)+'\n')
f.close()
