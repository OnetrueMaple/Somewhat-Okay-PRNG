from time import perf_counter, sleep

'''     Some ideas:
    Try getting a single bit in a matrix of zeroes to move to each and every other bit in the matrix the same number of times per cycle length, no matter its starting position.
    Try doing the same thing ^ but while adding 1s to the matrix and without overwriting the initial 1 you started with.
    Try doing ^ with variable matrix sizes.
'''

limit = 2 ** 32                                 # 32 bit integer limit.
space_size = "00000000000000000000000000000000" # 32 bits of 0.

'''------------------------------------------------------------------------'''
# Dictionary to convert hexadecimal numbers into binary.
charval =  {"0": "0000", "1": "0001", "2": "0010", "3": "0011",
            "4": "0100", "5": "0101", "6": "0110", "7": "0111",
            "8": "1000", "9": "1001", "a": "1010", "b": "1011",
            "c": "1100", "d": "1101", "e": "1110", "f": "1111"}

# Actually does the conversion from hexadecimal to binary...
def convToBin(num):
    seed = ""
    for i in range(len(num)):
        seed += charval[num[i]]
    return seed

# Python does not include a bit rolling function that I could find. I guess I'll make one myself
def leftroll(num, bits):
    rollamt = bits % 32
    value = bin(num)[2:]
    for bit in range(len(space_size) - len(value)):
        value = "0" + value
    value = int((value[(rollamt):] + value[:(rollamt)]), 2) # Moves the 'bits' on the left to the right
    return value

'''------------------------------------------------------------------------'''

# ChaCha20 requires I swap endianness a couple of times, so I need a function for that. I'm not actually sure whether the design follows that correctly, but I can at least copy
#   what they're doing on the page.
def swapBytes(num):
    new  = num % limit # Enforcing global maximum since this function expects an int
    temp = hex(new)[2:]

    # The size of the string should never be more than 8 chars since I took the '% limit' before checking.
    if(len(temp) < 8): # Pad the number with zeroes on the right if it doesn't occupy all 32 bits
        for i in range(8 - len(temp)):
            temp = f"0{temp}"

    # Since the number should certainly be 8 chars long...
    new = int(f"{temp[6:]}{temp[4:6]}{temp[2:4]}{temp[:2]}", 16)
    return new

def serialize(state):
    if(not isinstance(state, list)):
        print(f"serialize() only works on chacha states! That means only lists containing 16 integers! Got {type(state)} instead!")
        raise AssertionError
    if(len(state) != 16):
        print(f"serialize() only works on chacha states! That means only lists containing 16 integers! Got a list of {len(state)} elements instead!")
        raise AssertionError
    for i in range(16):
        if(not isinstance(state[i], int)):
            print(f"Found an incorrect datatype at {i} inside state list! serialize() only works on chacha states! That means only lists of 16 ints!")
            raise AssertionError

    nums = [] # List of all bytes in the specified order
    for i in range(16): # Starting at 2 since hex() returns string starting with '0x', indexes 0 and 1
        temp = hex(state[i])[2:]
        if(len(temp) < 8):
            for i in range(8 - len(temp)):
                temp = f"0{temp}"
        nums.append(int(temp[6: ], 16))
        nums.append(int(temp[4:6], 16))
        nums.append(int(temp[2:4], 16))
        nums.append(int(temp[0:2], 16))

    return nums

def chachaQuarterRound(state, a, b, c, d):
    state[a] += state[b]             # a + b
    state[a] %= limit
    state[d] ^= state[a]             # d ^ a
    state[d] = leftroll(state[d], 16)# d << 16
    state[c] += state[d]             # c + d
    state[c] %= limit
    state[b] ^= state[c]             # b ^ c
    state[b] = leftroll(state[b], 12)# b << 12
    state[a] += state[b]             # a + b
    state[a] %= limit
    state[d] ^= state[a]             # d ^ a
    state[d] = leftroll(state[d], 8) # d << 8
    state[c] += state[d]             # c + d
    state[c] %= limit
    state[b] ^= state[c]             # b ^ c
    state[b] = leftroll(state[b], 7) # b << 7
    return None

# Performs the chacha block encryption algorithm.
def chacha_block(keys, nonces, counter):

    # Python is so permissive that I have to be very thorough about checking datatype compatibility.
    valid_struc = True
    if(not isinstance(keys, list) or not isinstance(nonces, list) or not isinstance(counter, int)):
        if(not isinstance(keys, list)):
            print(f"Keys must be a list of integers 8 entries long! Got '{type(keys)}' instead of a list!")
            valid_struc = False
        if(not isinstance(nonces, list)):
            print(f"Nonces must be a list of integers 3 entries long! Got '{type(nonce)}' instead of a list!")
            valid_struc = False
        if(not isinstance(counter, int)):
            print(f"Counter must be an integer! Got '{type(counter)}' instead of an integer!")
            valid_struc = False
    # If any data type is incorrect, raise error
    if(not valid_struc):
        raise AssertionError

    # Now that I know keys and nonces are indeed lists...
    if(len(keys) != 8): # Check for the correct length...
        print(f"Keys must be a list of integers 8 entries long! Got '{len(keys)}' entries instead of 8!")
        valid_struc = False
    if(len(nonces) != 3):
        print(f"Nonces must be a list of integers 3 entries long! Got '{len(nonces)}' entries instead of 3!")
        valid_struc = False
    # If length expectations aren't met, raise error
    if(not valid_struc):
        raise AssertionError

    # Now that I know list sizes are exactly what they need to be, validate the datatype of each index...
    for i in range(8):
        if(not isinstance(keys[i], int)):
            valid_struc = False
    if(not valid_struc):
        print(f"Keys must be a list of integers 8 entries long! Wrong datatypes were present instead of integers!")
        valid_struc = False
    for i in range(3):
        if(not isinstance(nonces[i], int)):
            valid_struct = False
    if(not valid_struc):
        print(f"Nonces must be a list of integers 3 entries long! Wrong datatypes were present instead of integers!")
        valid_struc = False

    # And if any check fails, raise AssertionError. The relevant error messages should help somebody fix their usage.
    if(not valid_struc):
        raise AssertionError

    # If we got this far, then we are good to go!
    state = [ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
              swapBytes(keys[0]), swapBytes(keys[1]), swapBytes(keys[2]), swapBytes(keys[3]),
              swapBytes(keys[4]), swapBytes(keys[5]), swapBytes(keys[6]), swapBytes(keys[7]),
              (counter % limit),  swapBytes(nonces[0]), swapBytes(nonces[1]), swapBytes(nonces[2])]

    initial = []    # I have to manually recreate a copy, python compiler creates shallow copies.
    for i in range(16):
        initial.append(state[i])

    for i in range(10):
        chachaQuarterRound(state, 0, 4, 8, 12)
        chachaQuarterRound(state, 1, 5, 9, 13)
        chachaQuarterRound(state, 2, 6, 10, 14)
        chachaQuarterRound(state, 3, 7, 11, 15)
        chachaQuarterRound(state, 0, 5, 10, 15)
        chachaQuarterRound(state, 1, 6, 11, 12)
        chachaQuarterRound(state, 2, 7, 8, 13)
        chachaQuarterRound(state, 3, 4, 9, 14)

    for i in range(16):
        state[i] += initial[i]
        state[i] %= limit

    return serialize(state)

def test_chacha():
    # I will be using the default values provided inside the ChaCha20 design specifications listed: https://datatracker.ietf.org/doc/html/rfc8439

    # Some initialization data, or two 'passwords' one each from two people.
    keys    = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f]
    # Another set of initialization data, or a shared key between two people used once per cycle.
    nonces  = [0x00000009, 0x0000004a, 0x00000000]
    # Tick upwards to advance state
    counter = 0x00000001

    data = chacha_block(keys, nonces, counter)

    correct = [
                0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
                0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
                0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
                0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e ]

    valid = True
    print(f"Validating the output of chacha_block() against a known correct test vector...")
    if(len(data) != len(correct)):
        print(f"Lengths of data and correct differ! correct: {len(correct)} data: {len(data)}")
        valid = False
    for i in range(len(correct)):
        if(data[i] != correct[i]):
            print(f"Values at {i} differ! Correct: {hex(correct[i])[2:]} Data: {hex(data[i])[2:]}")
            valid = False

    if(not valid):
        print("Incorect implementation!")
    else:
        print("Everything looks good!")

def test_rng():
    start = None
    finish = 0

    # Some garbage data
    keys    = [0x66292716, 0xABC6767A, 0xBCBCADAD, 0x21345678, 0x87654321, 0xFEDCBA98, 0x77777769, 0xAAAAAAAA]
    nonces  = [0xBBBBBBBB, 0xEEEEEEEE, 0x10101010]
    counter = 0x0

    start = perf_counter()
    nums = 500000
    vals = ""
    while(len(vals) < nums):
        block     = chacha_block(keys, nonces, counter)
        for i in range(len(block)):
            vals += bin(block[i])[2:]
        counter  += 1
    finish = perf_counter() - start
    print(f"seed=\n{vals}")
    print(f"Length = {len(vals)}")
    print(f"{'\033[94m'}Generation time: {'\033[91m'}{finish:.6f}s")

if __name__ == "__main__":
    test_chacha()

'''
#VARIOUS TESTING THINGS
def thing1():
    num = int("0b11111111111111110000000000000000", 2)
    print(f"Num={num}, num(b)={bin(num)}, num(F)={hex(num)}")
    num = leftroll(num, 34)
    print(f"after left roll 2: {num}, (b): {bin(num)}, (F): {hex(num)}")

def thing2():
    max_num = int("0b11111111111111111111111111111111", 2)
    print(f"max_num         ={max_num}, max_num(b)={bin(max_num)},   max_num(F)={hex(max_num)}")
    print(f"limit           ={limit}, limit(b)  ={bin(limit)},   limit(F) ={hex(limit)}")
    print(f"max_num % limit ={max_num % limit}, oper(b)   ={bin(max_num % limit)},      oper(F)={hex(max_num % limit)}")
    actual_limit = 4294967296
    print(f"actual          ={actual_limit}, actual(b) ={bin(actual_limit)}, actual(F)  ={hex(actual_limit)}")

def test_bit():
    #stateA = [0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]
    #chachaQuarterRound(stateA, 0, 1, 2, 3)
    #strin = "["
    #for i in range(len(stateA)):
    #    strin += f"{hex(stateA[i])}, "
    #print(f"stateA={strin[:-2]}]")
    num = 2147483648
    print(f"before left roll: {num}\nafter left roll: {leftroll(num, 1)}")
'''