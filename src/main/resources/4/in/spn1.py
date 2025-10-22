
###############
# SPN1
###############


class SPN1():

    #p-box
    p = [0, 4, 8, 12, 1, 5,
         9, 13, 2, 6, 10, 14,
         3, 7, 11, 15]

    #S-box
    s = [14, 4, 13, 1, 2, 15, 11, 8,
         3, 10, 6, 12, 5, 9, 0, 7]

    # s-box
    def sbox(self, x):
        return self.s[x]

    # p-box
    def pbox(self, x):
        y = 0
        for i in range(len(self.p)):
            if (x & (1 << i)) != 0:
                y ^= (1 << self.p[i])
        return y


    # break into 4-bit chunks
    def demux(self, x):
        y = []
        for i in range(0, 4):
            y.append((x >> (i*4)) & 0xf)
        return y


    #convert back into 16-bit state
    def mux(self, x):
        y = 0
        for i in range(0, 4):
            y ^= (x[i] << (i*4))
        return y

    def round_keys(self, k):
        rk = []
        rk.append((k >> 16) & (2**16-1))
        rk.append((k >> 12) & (2**16-1))
        rk.append((k >> 8) & (2**16-1))
        rk.append((k >> 4) & (2**16-1))
        rk.append(k & (2**16-1))
        return rk

    # Key mixing
    def mix(self, p, k):
        v = p ^ k
        return v

    #round function
    def round(self, p, k):
        #XOR key
        u = self.mix(p, k)
        v = []
        # run through substitution layer
        for x in self.demux(u):
            v.append(self.sbox(x))
        # run through permutation layer
        w = self.pbox(self.mux(v))
        return w

    def last_round(self, p, k1, k2):
        #XOR key
        u = self.mix(p, k1)
        v = []
        # run through substitution layer
        for x in self.demux(u):
            v.append(self.sbox(x))
        #XOR key
        u = self.mix(self.mux(v), k2)
        return u

    def encrypt(self, p, rk, rounds):
        x = p
        for i in range(rounds-1):
            x = self.round(x, rk[i])
        x = self.last_round(x, rk[rounds-1], rk[rounds])
        return x

    # encrypt list of 16-bit values using provided key and number of rounds
    def encrypt_data(self, data, key, rounds):
        rk = self.round_keys(key)
        out = []
        for value in data:
            out.append(self.encrypt(value, rk, rounds))
        return out


def main():
    e = SPN1()
    x = int('1010010100010111', 2)
    rounds = 4
    k = int('01101100011101010100111100100001', 2)
    rk = e.round_keys(k)
    y = e.encrypt(x, rk, rounds)
    print('y={}'.format(bin(y)[2:].zfill(16)))


if __name__ == '__main__':
    main()