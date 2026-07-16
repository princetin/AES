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

def hex_xor_matrices(mat1, mat2):
    # Конвертируем строки в числа
    vec_func = np.vectorize(lambda x, y: f"{int(x, 16) ^ int(y, 16):02x}")
    return vec_func(mat1, mat2)


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



def pading_block(block, size=16, pad_value='0c'):
    while len(block) < size:
        block.append(pad_value)
    return block