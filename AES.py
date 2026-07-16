from XOR import hex_xor_matrices
from XOR import pading_block
from XOR import SBOX
from XOR import replacement_S_box
import secrets
import numpy as np
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes



def aes(message: str, p, g):
    private_secret1 = secrets.randbelow(p - 2) + 1
    private_secret2 = secrets.randbelow(p - 2) + 1

    A = pow(g, private_secret1, p)
    B = pow(g, private_secret2, p)
    secretKey1 = pow(B, private_secret1, p)
    secretKey2 = pow(A, private_secret2, p)

    MyError = type('MyError', (Exception,), {})

    if secretKey1 == secretKey2:
        secretKey = secretKey1
    else:
        raise MyError('Ошибка! Ключи secretKey1 и secretKey2 не равны (они известны только отправителю и адресату')

    number_bytes = secretKey.to_bytes((secretKey.bit_length() + 7) // 8, 'big')
    hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"")
    short_key = hkdf.derive(number_bytes)
    short_key = short_key.hex()
    short_key = ' '.join(short_key[i:i + 2] for i in range(0, len(short_key), 2)).split()

    short_key_matrix = np.array(short_key).reshape(4, 4).T


    message_byte = message.encode('utf-8').hex(' ').split()

    block_size = 16
    blocks = [message_byte[i:i+block_size] for i in range(0, len(message_byte), block_size)]

    for i, block in enumerate(blocks):
        if len(block) < 16:
            blocks[i] = pading_block(block, 16, '0c')

    for elements_in_blocks in blocks:
        State_matrix = np.array(elements_in_blocks).reshape(4, 4).T
        RK_xor_matrix = hex_xor_matrices(State_matrix, short_key_matrix)
        #print(RK_xor_matrix)
        RK_xor_matrix = np.array([[int(x, 16) for x in row] for row in RK_xor_matrix])

        vectorized_sbox = np.vectorize(replacement_S_box)
        result_numbers = vectorized_sbox(RK_xor_matrix)
        SubBytes_matrix = np.array([[f'{x:02x}' for x in row] for row in result_numbers])
        #print(SubBytes_matrix)

        Shifted_roll_matrix = np.array([
            SubBytes_matrix[0],
            np.roll(SubBytes_matrix[1], -1),
            np.roll(SubBytes_matrix[2], -2),
            np.roll(SubBytes_matrix[3], -3)
        ])
        print(Shifted_roll_matrix)




RFC_3526 = 32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559

print(aes('здарова чевак', RFC_3526, 2))