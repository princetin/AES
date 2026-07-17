from XOR import hex_xor_matrices
from XOR import pading_block
from XOR import mix_columns
from XOR import RFC_3526
from XOR import replacement_S_box
from XOR import key_expansion
import secrets
import numpy as np
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def sub_bytes(state_hex_matrix):
    state_ints = np.array([[int(x, 16) for x in row] for row in state_hex_matrix])
    vectorized_sbox = np.vectorize(replacement_S_box)
    result_numbers = vectorized_sbox(state_ints)
    return np.array([[f'{x:02x}' for x in row] for row in result_numbers])


def shift_rows(state_hex_matrix):
    return np.array([
        state_hex_matrix[0],
        np.roll(state_hex_matrix[1], -1),
        np.roll(state_hex_matrix[2], -2),
        np.roll(state_hex_matrix[3], -3)
    ])



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

    # раунд-ключи для начального AddRoundKey + 10 раундов AES-128
    round_keys = key_expansion(short_key_matrix, rounds=10)

    message_byte = message.encode('utf-8').hex(' ').split()

    block_size = 16
    blocks = [message_byte[i:i+block_size] for i in range(0, len(message_byte), block_size)]

    for i, block in enumerate(blocks):
        if len(block) < 16:
            blocks[i] = pading_block(block, 16, '0c')

    ciphertext_blocks = []

    for elements_in_blocks in blocks:
        State_matrix = np.array(elements_in_blocks).reshape(4, 4).T

        # начальный AddRoundKey (round 0)
        State_matrix = hex_xor_matrices(State_matrix, round_keys[0])

        # раунды 1..9: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
        for round_num in range(1, 10):
            SubBytes_matrix = sub_bytes(State_matrix)
            Shifted_roll_matrix = shift_rows(SubBytes_matrix)

            Shifted_roll_ints = [[int(x, 16) for x in row] for row in Shifted_roll_matrix]
            MixColumns_matrix = mix_columns(Shifted_roll_ints)
            MixColumns_hex = np.array([[f'{x:02x}' for x in row] for row in MixColumns_matrix])

            State_matrix = hex_xor_matrices(MixColumns_hex, round_keys[round_num])

        # финальный, 10-й раунд: SubBytes -> ShiftRows -> AddRoundKey (без MixColumns)
        SubBytes_matrix = sub_bytes(State_matrix)
        Shifted_roll_matrix = shift_rows(SubBytes_matrix)
        State_matrix = hex_xor_matrices(Shifted_roll_matrix, round_keys[10])

        ciphertext_blocks.append(State_matrix.T.flatten())

    ciphertext = ''.join(''.join(block) for block in ciphertext_blocks)
    return ciphertext



print(aes('здарова чевак', RFC_3526, 2))