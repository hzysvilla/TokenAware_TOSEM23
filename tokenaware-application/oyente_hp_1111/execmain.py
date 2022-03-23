import os

codepath = 'code/codecollect'
def write(path, mode, data):
    with open(path, mode) as f:
        f.write(data)
    f.close()

write('abiresult', 'w', '')
count = 0
with open(codepath, 'r') as f:
    for line in f:
        count += 1
        #if count != 5:
        #    continue
        info = line[0:len(line)-1].split('#')
        addr = info[0]
        code = info[1]
        if int(len(code)/2)*2 != len(code):
            code = code[0:len(code)-1]
        write('tempcode', 'w', code)
        write('abiresult', 'a', 'addr#'+addr+'\n')
        os.system('time python oyente.py -s tempcode -b')
        #if count == 5:
        #    exit()
f.close()
