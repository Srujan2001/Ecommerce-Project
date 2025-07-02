import random
l=[chr(i) for i in range(ord('A'),ord('Z')+1)]
l2=[chr(i) for i in range(ord('a'),ord('z')+1)]
def genotp():
    gotp=''
    for i in range(0,2):
        gotp=gotp+random.choice(l)
        gotp=gotp+random.choice(l2)
        gotp=gotp+str(random.randint(0,9))
    return gotp
