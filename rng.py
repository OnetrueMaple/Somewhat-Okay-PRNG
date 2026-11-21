# THIS PROJECT WAS MADE ON LINUX MINT 22.1, USING PYTHON 3.12!! If it fails to compile/run, ensure that you are at least using python 3.12 before reporting errors.
from time import perf_counter, sleep
from hashlib import sha512

# Entropy as "defined in physics" *seems to be* how many "situations" are possible to reach. The universe has physical laws that only makes certain ones reachable. We can
#   find these laws by watching things happen and experimenting, and trying to predict what happens next "this time". Our rules measure state transitions, basically. When we measure
#   something, we decide that only certain things matter. As long as we pay attention only to what we decide is important, we can predict the future... except when entropy comes in.
# Basically: (set of all possible states) x (measurement) ~> (less states). Entropy counts how much you're losing track of with a measurement because those other states don't disappear.
# Computers rarely ever get to perform measurements in code. That means everything is "deterministic", or completely predictable given that you know the starting values.
# Random number generators, when set up correctly, provide a way for programs to have "unpredictable" behavior across runs. Mersenne Twister (an old PRNG) provided numbers that
#   looked random... but really it just moved from one point in a sequence to the next. That sequence was each digit in the number 2^19937 - 1. It's easy to see that isn't random.
# Most PRNGs have a problem like this... and I'd like to make a generator that doesn't.

# I want this as close to cryptographically secure as possible, just because setting an absurdly high bar makes development interesting.
# Cryptographic security requires not being able to predict future outputs or being able to access/correctly guess internal values. Software alone can't do that second part, and the first is hard.
# There's also an issue with my measurements being biased and necessarily correlated... and that cybersecurity keeps moving forward. Nothing stays secure forever.
# I won't claim security capability... but I will chase the dream despite these problems.

'''
  Current system I'm designing around to achieve this:

    - Entropy Source (anything I can measure which provably varies *somewhat* in value. It doesn't need to be perfect, but less correlated/biased sources and mixing sources helps)
    - Entropy Pool   (collection of measurements I can use as the "seed" for a PRNG)
    - PRNG/DRBG      (function which uses a seed to generate a "random" number)
    - CS Things      (stuff I don't fully understand yet. The current idea is that I feed my PRNG outputs into some "secure" stuff so it becomes harder to hack/predict)
        ^ On this... Stream ciphers (ChaCha20) or hash functions (SHA256/SHA512) are pretty good baselines, but cannot guarantee "secure randomness". That's a property
          of the entire program doing all its jobs well, and still impossible given that I've chosen to stay software-only.

  To ensure maximum unpredictability is preserved my program needs to handle its parts very carefully. It requires:

    - Entropy sources have their correlations destroyed and biases minimized. Every source is a measurement of something, so they're all correlated by necessity.
    - PRNG output range cannot favor certain outputs (bias). Seed cycling can't be left unchecked, otherwise the overlap skews frequencies (bias) towards certain states.
    - Every possible state be reachable. For bit streams, the number of possible states is 2^n. Each one must be reachable with the same frequency as every other state.

  To ensure that this is cryptographically secure where it can be... I need to thoroughly test very specific properties of my outputs. Those properties are:

    - Irreversible CSPRNG function. I cannot let an output be reconverted into the seed used to generate it.
    - Entropy sources and pool cannot be guessable by a user. If users can predict my source, PRNG outputs are relatively trivial to predict using my algorithm.
    - Outputs from my CSPRNG cannot contain patterns which give users information about the PRNG or entropy source. Stats tests and reseeding *help* with this.

        Specifically, *betting on any set of outcomes* cannot be more effective than brute forcing all possible states. Maintaining this property regardless of intrusion
        is the measure of cryptographic security. That's obviously impossible if somebody can access the internal state... but we can get "secure for now". I'll try to push the
        boundary where I can when I'm able to. For now, I catch up and learn what I can.

  I will likely add to and change this as I make progress.
'''

# End of random bullshit rambling
'''----------------------------------------------------------------------------------------------------------------'''
# Start of fundamental requirements (entropy source, prng algorithm or hash/encryption algorithm)

limit = 2 ** 32                                 # 32 bit integer limit.
space_size = "00000000000000000000000000000000" # 32 bits of 0.

# Don't know how I derive these, nor if I should derive them from something. These are the ones ChaCha uses in its standard implementation. I'm just gonna trust the guy for now.
constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

# Will gather a bunch of measurements and add/xor them together to create these at runtime. I'll also need a way to convert a string or a passed number into a set of keys.
keys = [0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0]

# 32-Bit representation for how many state evolutions have happened. This value will be used to keep track of outputs without reseeding the algorithm despite repeating encryption cycles.
counter = 0x00000000
'''
#   Calculating this properly is required when trying to keep track of entropy bits. When you're just deterministically shuffling bits that came from transformations of data
#   instead of bits that came from measurements, you've already lost what you needed most (besides a god-tier PRNG I guess).
'''

# This effectively represents the uniqueness of each instance. Make sure that any operations/reseeds do not destroy any information here! (No modulus, subtraction, division)
nonces = [0x0, 0x0, 0x0]
'''
#   The maximum theoretical cycle length is calculated by using each hexadecimal digit as 4 digits in a binary number. Charval below shows this is possible.
#   16 values each 8 digit hexadecimal, each digit is 4 bits (8 hex digits * 4 bits = 32 bits), 32 bits * 16 values = 512 binary digits
#   512 Binary digits can represent any number within 2^512 - 1. That number is: 1.34 * 10^154 with three significant figures (losing accuracy past 2 decimal places)
#   That means the cycle length should be roughly 1.34 * 10^154 if we assume that the PRNG/ChaCha Algorithm has our ideal state evolution properties. Make sure to check for this! Keep it close!
#   However, if these algorithms do exactly what I need, then 1.34 * 10^154 possible outputs is *more* than enough.
'''

#'''
# I need a way to generate a key for the chacha state. I'll need to do this repeatedly upon initialization and for reseeding.
def keyGen(values):
    if not isinstance(values, list):
        print(f"Only put a list of ints into keygen!")
        raise TypeError
    for i in values:
        if not isinstance(i, int):
            print(f"Found {type(values[i])} inside of list, keygen only takes ints!")
            raise TypeError
    # If we get here, we're good to go!
    key = 0x0
    index = 0 # Keeps track of how many values I've used.

    while (index < len(values)):
        temp = ""
        while(len(temp) <= 8 and index < len(values)):
            temp += hex(values[index])[2:] # String the numbers together sequentially to occupy all 32 bits. Basic addition requires too many operations to get there, and is biased towards a value lol.
            index += 1
        if(index >= len(values) and temp == ""):
            temp = "0" # Setting to 0 to prevent errors and also to avoid overwriting entropy bits.
        key += int(temp, 16) # Add temp value to key...
        key %= limit         # And keep between 32-bit limit
        temp = ""
        while(len(temp) <= 8 and index < len(values)):
            temp += hex(values[index])[2:]
            index += 1
        if(index >= len(values) and temp == ""):
            temp = "0" # Setting to 0 to prevent errors and also to avoid overwriting entropy bits.
        key ^= (int(temp, 16) % limit) # This time, xor the two values.
        # Repeat this until all values exhaused
    return key

def calcNonces(): # Tries to generate a number that combines all previous states, to preserve state uniqueness.
    global limit
    global keys
    global nonces
    # Keys 3 and 4 are unused at the moment. 3 doesn't divide 8 evenly, I'm still unsure what to do about this.
    nonces[0] ^= ( ((keys[0] + keys[5]) ) % limit )
    nonces[1] ^= ( ((keys[1] + keys[6]) ) % limit )
    nonces[2] ^= ( ((keys[2] + keys[7]) ) % limit )
    return None

#'''
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
    rollamt = bits % 32 # Saves loop cycles, also not doing this makes avoiding out-of-bounds calls on the string harder.
    value = bin(num)[2:]
    for bit in range(len(space_size) - len(value)):
        value = "0" + value
    value = int((value[(rollamt):] + value[:(rollamt)]), 2) # Moves the 'bits' on the left to the right
    return value

'''------------------------------------------------------------------------'''

# ChaCha20 requires I swap endianness a couple of times, so I need a function for that. I'm not actually sure whether the design follows "endianness" exactly, but I can at least copy
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

def to_string(data):
    if(not isinstance(data, list)):
        print(f"to_string() requires a list of integers!")
        raise AssertionError
    values = ""
    for i in range(len(data)):
        values += f"{data[i]}"
    return values

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
''' End of Encryption Algorithm '''

#'''
# I need a *very* large string (5MB at least) to increase TLB Miss Chance...
# I need to learn more about how memory access works to make this more effective.
print(f"{'\033[94m'}Making large string...")
start = perf_counter()

strinSize = 7 * 1000 * 1000 # 1B * 1000 -> KB... * 1000 -> MB... * 7 -> 7MB
# Using bytearrays makes ABSOLUTELY SURE that the entire variable is assigned one memory location rather than split up across many. Compilers handle quite a lot
#   behind the scenes, holy...
strin1 = bytearray(strinSize)
for i in range(strinSize):
    strin1 += bytearray(0)
finish = perf_counter() - start
print(f"{'\033[94m'}Done with string in {'\033[91m'}{finish:.5f}s!")
#'''

'''
    This code is what should be modified if/when a better source of "randomness" is available/required. Got lava lamps and pngs? This function should make that
    data useable for the rest of the program. I will be using time since I'm locked to one machine with no external sensors. But to be quite honest,
    timing entropy alone has far too much bias to be usable. Bias means that measurement values end up in some places more often than others.
    For example, if I travel 20 minutes to work every day and rarely travel anywhere else, my travel times across all outings will be "biased" towards 20 minutes.
    Bias isn't all that matters though. Every single source, even quantum state measurements, are correlated with something and those correlations create patterns in data.
    So, each measurement requires *some* amount of hashing to destroy those patterns. 20km is correlated with distance, 20 minutes is correlated with time, ect.
    Measurements are often correlated with several other hidden factors... for my timing measurements here: my pc specs, physical PC status, and OS influence
    the time it takes for code to execute. So when I measure task completion time, I'm also measuring the factors that influence them. Those factors are "correlated" with my times.
    Hashing doesn't completely fix correlation (especially if done poorly), but it helps manage correlations pretty effectively since the form of the measurements get scrambled across bits.
    I should note that hashing hardly addresses bias, *if at all*. If I'm sourcing poor entropy, my possible state probabilities will be skewed with my measurements irreversibly.
'''
def entropySource():
    start = perf_counter() # Starting timestamp...

    # I gotta do some stuff so that the computer can "take longer" and provide a wider range of times. I can't just have the same 2 or 3 values since
    #   they wouldn't be distributed evenly between the 2 or 3 values. For example, a ~70% 'chance' of a 6 and a ~30% 'chance' of a 5 is clearly "not random".
    # This is about min-entropy. The idea is that I want every bit measured to have as close to 50% chance as possible for either a 0 or 1. Anything more or less
    #   becomes biased and that goes against what I eventually want this generator to accomplish.
    sleep(0)                                        # Creates a cpu scheduler task. Causes a lot of timing variance even if set to 0.
    temp1 = strin1[int(start) % strinSize]          # Attempts to make a cache miss.

    finish = perf_counter() - start # Finished timestamp.
    return int(finish * 1e9) # The perf_counter timestamps are "accurate" down to nanoseconds. I might as well have those be my standard units.
'''
# This only returns variation in time measurements influenced by: cpu scheduling, temperature throttling, and cache misses.
# If I try too hard to make cache misses happen, the timestamps become too correlated with these ^ factors (and my OS behavior) and begin to fail stats tests.
# That said, I'm told Linux is very consistent with it's CPU cycle timing, so the self correlation between measurements will be pretty high. Unfortunate for me.
'''

# List of measurements. Usually CSPRNGs will mix several different kinds of measurements, I will only be using time. More on that below.
entropyPool = [ ]
'''
# dev/urandom actually measures *a lot* of different sources, not just CPU timing variance. Sourcing entropy from multiple places is really good because it means there is more information
#   to separate and track forwards/backwards. Since measurements themselves are what's being used to choose which numbers to output, having more types of measurements
#   is the only sure way I know of to make this generator stronger. For now, I will not be using this strategy. I'd rather not
#   complicate an already delicate problem by making the logistics far harder to track. I understand that this is kind of the point, but gaps in *my* understanding are certainly not
#   a good measure for how good this generator is. I'd rather be able to prove the same gap will exist for everyone, and until I can do so I will not be utilizing extra entropy sources.
'''

# The entropy pool is necessary to maintain "forward secrecy". I don't want to rely on one measurement over and over again, or consecutively call from the
#   same, biased entropy source too many times. ESPECIALLY not when timing measurements are biased as strongly as they are.
# This turns a passed seed into an entropy pool which gets consolidated into the generator state immediately. Since the point of seeds is to repeat behavior, I may need to
#   find a way to have the seed deterministically fill the entropy pool and set nonces.
def refillEntropyPool(seed):
    global entropyPool
    if(seed == None):
        while(len(entropyPool) < 100): # Hardcoding number of values for testing.
            entropyPool.append(entropySource())
    else:
        if not isinstance(seed, list):
            print(f"Please sanitize your seed into a list of ints before passing them into the generator!")
            raise TypeError
        for i in range(len(seed)):
            entropyPool.append(seed[i]) # I'm questioning my judgement so hard right now.

# Finally, we get to create states by seeds or by the whims of whatever the fuck probability is feeling at the moment.
# I need to start doing some systematic accounting of entropy bits so I know when to reseed the generator.
def reinitializeState(seed=None):
    global constants
    global keys
    global counter
    global nonces
    global state

    if(seed == None):
        refillEntropyPool(seed)

        constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        #'''
        for i in range(len(keys)): # Pretty sure the correct number is 8 in place of len(keys) but whatever.
            temp = []
            for j in range(10):
                temp.append(entropyPool.pop(0))
            keys[i] = keyGen(temp)
        counter = 0x00000000
        calcNonces()
        #'''

def genNumber(length, seed=None): # Sisyphus function (carries the program)
    global keys
    global nonces
    global counter
    vals = ""

    # If no seed, then I will reseed the chacha state and entropy pool. This is my default while testing, for practial usage it shouldn't reseed every call since that's expensive.
    if(seed == None):
        reinitializeState(seed) # Make sure each generation cycle is running a fresh state.
        while(len(vals) < (length / 4)):
            # Generator state shouldn't be outputted because it gives people a way to track state evolution, because chacha state evolution is reversible.
            #   Instead of using the state as output, I'll hash the state using sha512 since it's an irreversible function.
            vals += str(sha512((to_string(chacha_block(keys, nonces, counter))).encode('utf-8')).hexdigest())
            counter += 1

    else:   # Seeded number generation so I can repeat stuff for when I use this in other projects.
        return None

    number = ""
    for i in range(len(vals)):
        number += charval[vals[i]]

    return number


# End of fundamental requirements... entropy source (measure time), constant data structure (chacha20 + hash)...
'''----------------------------------------------------------------------------------------------------------------'''
# Start of testing code...

'''
FOR ANYONE INTERESTED IN CRYPTOGRAPHIC SECURITY: DO NOT USE THIS AS IS. I CANNOT STRESS THAT ENOUGH!

https://mzsoltmolnar.github.io/random-bitstream-tester/
^ this is for testing the streams. This program passes all tests *usually* except for runs test which it fails ~60-70% of the time at medium-to-large bitstream lengths.
    This is probably because I'm collecting entropy from time measurements, among a few other factors that I haven't managed correctly, if at all, so far.
    Passing tests doesn't necessarily mean you have a CS Secure RNG, and even if mine performs *okay* on that front, there are a few faster, and higher quality options available elsewhere.
    ChaCha20 and Shishua are solid, and you can find their algorithms and implementation details here:
        ChaCha20: https://datatracker.ietf.org/doc/html/rfc8439
        Shishua:  https://espadrine.github.io/blog/posts/shishua-the-fastest-prng-in-the-world.html
    Good luck o7
'''

def test():
    #'''
    stop   = ""
    toFile = False
    nums = 1 * 1000 * 1000 # Each char is 1 byte, 1000 chars = 1000 bytes = 1 KB....
    while(stop == ""):
        print(f"{'\033[94m'}Generating {nums} bits...")
        genstart = perf_counter()
        seed = genNumber(nums)
        genfinish = perf_counter() - genstart

        if(toFile == False): # Just print the output to a terminal.
            print(f"{'\033[93m'}Seed:\n{seed}")
            print(f"{'\033[95m'}Length:                          {len(seed)}")
        else:                # Print the output to a file for testing with PractRand, Dieharder, and NIST Test Suite
            writestart = perf_counter()
            print(f"{'\033[94m'}Saving string to file...")
            f = open("temp.txt", "w", encoding="utf-8")
            f.write(seed)
            f.close()
            writefinish = perf_counter() - writestart
            print(f"{'\033[94m'}Saving time: {'\033[91m'}{writefinish:.6f}s")

        print(f"{'\033[94m'}Generation time: {'\033[91m'}{genfinish:.6f}s")
        stop = str(input())
    #'''

def readurandom():
    nums = 12#int(5 * (10 ** 6))
    number  = ""
    print(f"{'\033[94m'}Generating {nums} bits...")
    start = perf_counter()
    urandom = open("/dev/urandom", "rb")
    for i in range(nums):
        bytes   = urandom.read(1).hex()
        number += bytes[0] #charval[bytes[0]]
        number += bytes[1] #charval[bytes[1]]
    urandom.close()
    finish = perf_counter() - start
    print(f"{'\033[93m'}Bitstream:\n{number}")
    print(f"{'\033[95m'}Length:                          {len(number)}")
    print(f"{'\033[94m'}Generation time: {'\033[91m'}{finish:.6f}s")

if __name__ == "__main__": # Only runs the test code if rng.py was called to run via terminal/shell.
    test()