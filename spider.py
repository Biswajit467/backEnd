lst = [11, 12, 13, 14, 15, 16]
new_lst = []


for i in lst:
    dsum = 0
    while i != 0:
        ld = i % 10
        dsum += ld
        i //= 10
    new_lst.append(dsum)

print (new_lst)
