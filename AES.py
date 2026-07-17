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
    # secretKey (число, DH)  →  HKDF  →  short_key (16 байт, master key)  →  key_expansion  →  round_keys[0..10]
    round_keys = key_expansion(short_key_matrix, rounds=10)

    message_byte = message.encode('utf-8').hex(' ').split()

    block_size = 16
    blocks = [message_byte[i:i+block_size] for i in range(0, len(message_byte), block_size)]

    # paddind:
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
    print(secretKey)
    return ciphertext



print(aes('В настоящее время Рошаль является директором Московского НИИ неотло́жной детской хирургии и травматоло́гии. Леонид Михайлович не только талантливый врач и отличный организатор, но и очень мужественный человек. Он вёл переговоры с террористами, захватившими здание Театрального центра на Дубровке в Москве. Благодаря вмешательству Рошаля из здания было выведено восемь детей, заложникам удалось передать воду и медикаменты. За мужество и самоотверженность доктору были вручены́ премия «Национальный герой» и орден Мужества.Тимирязев получил прекрасное домашнее образование, поступил на естественное отделение физико-математического факультета СанктПетербургского университета. Он посещал лекции ведущих учёных, среди которых были химик Менделе́ев, физиолог Се́ченов, историк Костома́ров. Уже со студенческой скамьи Тимирязев наметил главное направление своей научной деятельности, которое сочетал с простыми, но оригинальными и точными приёмами исследования.Главным делом своей жизни Матвей Емельянович считал помощь простым людям. Он опекал нижегородский сиротский приют: жертвовал ему деньги, оплачивал обучение подросткам. Башкиров построил водокачку в селе Знамёнки, где у него была дача, и отремонтировал обветшалый сельский храм. У рабочих мукомо́льных заводов Матвея Башкирова были благоустроенные общежития, им платили пособия на детей, а когда в губернии случался неурожай, хозяин раздавал муку́ и зерно из своих хранилищ. В 1917 году большевики отобрали у Матвея Башкирова всё состояние. Умер он в нищете. Но построенные им мельница, училища, храмы и дома до сих пор служат людям.Рисовал Айвазовский с детства, учился в гимназии Симферополя, а затем в Академии художеств в Санкт-Петербурге, где занимался в классах пейзажной и бата́льной живописи. Во время учёбы работы художника были отмечены золотой и серебряной медалями. Благодаря успехам Айвазовского совет Академии принял необычное решение – завершить его обучение в Академии на два года раньше положенного срока и послать в Крым для самостоятельных работ, а потом – в командировку за границу. В начале 1873 года во Флоренции состоялась выставка картин Айвазовского, получившая много положительных отзывов. Он стал одним из наиболее признанных во всём мире представителей русской школы живописи. Интересно, что многие морские пейзажи художник создал по памяти, а не писал с натуры. Будущий русский учёный родился в многодетной семье, он был семнадцатым ребёнком. В детстве Менделе́ев не отличался прилежанием в учёбе, труднее всего ему давался латинский язык. На первом курсе нерадивый студент Главного педагогического института «провалил» все экзамены, кроме математики. Всё изменилось в конце обучения: Менделеев увлёкся химией. Он защитил диссертацию, вёл научную работу в Германии и России.В 1869 году, работая над учебником «Основы химии», Дми́трий Ива́нович Менделеев создал свою знаменитую Периодическую систему химических элементов. Учёный выяснил, что свойства известных в то время 63 химических элементов периодически повторяются, если расположить элементы в порядке возрастания их атомного веса. Опираясь на свою систему, Менделеев предсказал существование нескольких неизвестных тогда химических элементов и описал их свойства. Впоследствии все эти элементы были открыты.Дмитрий Иванович был разносторонним человеком: он изучал нефтяные месторождения, в одиночку совершил полёт на воздушном шаре, интересовался освоением А́рктики и разработал проект ледокола, основал Главную палату мер и весо́в в России. Менделеев много путешествовал. Одним из его необычных увлечений было изготовление чемоданов, которые отличались небывалой прочностью. Секрет заключался в особом клее, который учёный изобрёл сам.Деятельность Дмитрия Ивановича свидетельствует о силе ума, способного проникать в тайны природы, о безграничных возможностях познания.', RFC_3526, 2))