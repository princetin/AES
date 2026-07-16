def orange(x: bin, y: bin):
    result = 0
    if x == False and y == False:
        result = 0
    if x == False and y == True:
        result = 1
    if x == True and y == False:
        result = 1
    if x == True and y == True:
        result = 0

    return result


def xor(a: hex, b: hex):
    a, b = bin(a)[2:], bin(b)[2:]
    # 0xc1
    max_len = max(len(a), len(b))
    a = a.zfill(max_len)
    b = b.zfill(max_len)
    string = ''
    if len(a) == len(b):
        for i in range(len(a)):
            string += str(orange(int(a[i]), int(b[i])))

    return string.zfill(8)