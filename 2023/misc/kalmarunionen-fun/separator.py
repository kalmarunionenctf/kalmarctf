import sys

fname = sys.argv[1]

prefix = ""
if len(sys.argv)>2:
    prefix = sys.argv[2]

f=open(fname)
d=f.readlines()
f.close()

xarr = []
yarr = []
m = len(d)
for line in d:
    datatuple = eval(line)
    xarr.append(datatuple[0])
    yarr.append(datatuple[1])

marr = [abs(x)+abs(y) for x,y in zip(xarr,yarr)]
darr = [1 if x>1.3 else 0 for x in marr]
conseq0 = 0
conseq1 = 0
curlvl = 0
signnum = 0
lvlarr = []
lastlvlchange = 0

for i in range(len(darr)):
    if darr[i]==0:
        conseq0 += 1
        conseq1 = 0
    elif darr[i]==1:
        conseq1 += 1
        conseq0 = 0
    if conseq0>=4 and curlvl==1 and (i-lastlvlchange)>23:
        curlvl = 0
        signnum += 1
        print("Symbol " + str(signnum) + " length " + str(i-lastlvlchange) + " from " + str(lastlvlchange) + " to " + str(i))
        g=open(prefix + "-" + str(signnum) + ".txt", "w")
        for x in zip(xarr[lastlvlchange:i], yarr[lastlvlchange:i]):
            g.write(str(x) + "\n")
        g.close()
        lastlvlchange = i
    elif conseq1>=4 and curlvl==0:
        curlvl = 1
        #signnum += 1
    lvlarr.append(signnum)
