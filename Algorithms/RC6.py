import base64
import math


class RC6:
    def _XOR(self, *args):
        length = len(bin(max(args))[2:])
        args = [self._binExpansion(bin(arg), length)[2:] for arg in args]
        output = "0b"
        for x in range(length):
            counter = 0
            for arg in args:
                counter += int(arg[x])
            output += str(counter % 2)
        return int(output, 2)

    def _binExpansion(self, bit_string, length):
        output = bit_string
        while len(output) != length + 2:
            output = output[:2] + "0" + output[2:]
        return output

    def _circularShift(self, number, w, bits, side):
        bin_string = self._binExpansion(bin(number), w)
        bits %= w
        bin_string = bin_string[2:]
        if side == "left":
            return int("0b" + bin_string[bits:] + bin_string[:bits], 2)
        if side == "right":
            return int("0b" + bin_string[-bits:] + bin_string[:-bits], 2)

    def _generate_keysTable(self, key, w=32, r=20):
        mod = 2 ** w

        while len(key) % w != 0:
            key = key + "0"
        c = int(len(key) / w)
        L = [key[i * w : (i + 1) * w] for i in range(c)]
        L = [int("0b" + k, 2) for k in L]

        def Odd(number):

            if int(number) % 2 != 0:
                return int(number)
            else:
                return int(number) + 1

        f = (math.sqrt(5) + 1) / 2
        Qw = Odd((f - 1) * 2 ** w)
        Pw = Odd((math.e - 2) * 2 ** w)

        S = []
        S.append(Pw)

        for i in range(1, 2 * r + 4):
            S.append((S[i - 1] + Qw) % mod)

        A = B = i = j = 0
        v = 3 * max(c, 2 * r + 4)

        for s in range(1, v):
            A = S[i] = self._circularShift((S[i] + A + B) % mod, w, 3, "left")
            B = L[j] = self._circularShift(
                (L[j] + A + B) % mod, w, (A + B) % mod, "left"
            )
            i = (i + 1) % (2 * r + 4)
            j = (j + 1) % c

        self.keysTable = S
        return S

    def _encryption_binBlock(self, message, w=32, r=20):
        mod = 2 ** w
        S = self.keysTable

        A = int("0b" + message[0:w], 2)
        B = int("0b" + message[(w) : (2 * w)], 2)
        C = int("0b" + message[(2 * w) : (3 * w)], 2)
        D = int("0b" + message[(3 * w) : (4 * w)], 2)

        B = (B + S[0]) % mod
        D = (D + S[1]) % mod
        for i in range(1, r):
            t = self._circularShift(
                (B * ((2 * B) % mod + 1) % mod) % mod, w, int(math.log(w)), "left"
            )
            u = self._circularShift(
                (D * ((2 * D) % mod + 1) % mod) % mod, w, int(math.log(w)), "left"
            )
            A = (self._circularShift(self._XOR(A, t), w, u, "left") + S[2 * i]) % mod
            C = (
                self._circularShift(self._XOR(C, u), w, t, "left") + S[2 * i + 1]
            ) % mod
            aa, bb, cc, dd = B, C, D, A
            A, B, C, D = aa, bb, cc, dd

        A = (A + S[2 * r + 2]) % mod
        C = (C + S[2 * r + 3]) % mod

        output = ""
        output += self._binExpansion(bin(A), w)[2:]
        output += self._binExpansion(bin(B), w)[2:]
        output += self._binExpansion(bin(C), w)[2:]
        output += self._binExpansion(bin(D), w)[2:]

        return output

    def _decryption_binBlock(self, message, w=32, r=20):
        mod = 2 ** w
        S = self.keysTable

        A = int("0b" + message[0:w], 2)
        B = int("0b" + message[(w) : (2 * w)], 2)
        C = int("0b" + message[(2 * w) : (3 * w)], 2)
        D = int("0b" + message[(3 * w) : (4 * w)], 2)

        C = (C - S[2 * r + 3]) % mod
        A = (A - S[2 * r + 2]) % mod

        for j in range(1, r):
            i = r - j

            aa, bb, cc, dd = D, A, B, C
            A, B, C, D = aa, bb, cc, dd

            u = self._circularShift(
                (D * ((2 * D) % mod + 1) % mod) % mod, w, int(math.log(w)), "left"
            )
            t = self._circularShift(
                (B * ((2 * B) % mod + 1) % mod) % mod, w, int(math.log(w)), "left"
            )
            C = self._XOR(
                self._circularShift((C - S[2 * i + 1]) % mod, w, t % w, "right"), u
            )
            A = self._XOR(
                self._circularShift((A - S[2 * i]) % mod, w, u % w, "right"), t
            )

        B = (B - S[0]) % mod
        D = (D - S[1]) % mod

        output = ""
        output += self._binExpansion(bin(A), w)[2:]
        output += self._binExpansion(bin(B), w)[2:]
        output += self._binExpansion(bin(C), w)[2:]
        output += self._binExpansion(bin(D), w)[2:]

        return output

    def bytesToBin(self, bytes_string):
        output = bytearray(bytes_string)
        output = [self._binExpansion(bin(char), 8)[2:] for char in output]
        output = "".join(output)
        return output

    def binToBytes(self, bin_string):
        output = [
            int("0b" + bin_string[block * 8 : (block + 1) * 8], 2)
            for block in range(int(len(bin_string) / 8))
        ]
        output = bytes(output)
        return output

    def encryption(self, message, key, w=32, r=20):
        self._generate_keysTable(key, w=32, r=20)

        size = len(message)
        size = self._binExpansion(bin(size), 64)
        message = size[2:] + message

        while len(message) % (4 * w) != 0:
            message += "0"
        message = [
            message[(block * 4 * w) : ((block + 1) * 4 * w)]
            for block in range(int(len(message) / (4 * w)))
        ]

        output = ""
        for block in message:
            output += self._encryption_binBlock(block, w, r)
        return output

    def decryption(self, message, key, w=32, r=20):
        self._generate_keysTable(key, w=32, r=20)
        message = [
            message[x * w * 4 : (x + 1) * w * 4]
            for x in range(int(len(message) / (w * 4)))
        ]

        output = ""
        for block in message:
            output += self._decryption_binBlock(block, w=32, r=20)

        size = int("0b" + output[:64], 2)
        output = output[64 : 64 + size]
        return output

    def encryptImage(self, inputImagePath, outputImagePath, key):
        inp = open(inputImagePath, "rb")
        out = open(outputImagePath, "wb")
        message = inp.read()
        message = base64.b64encode(message)
        key = base64.b64encode(bytes(key, "utf-8"))
        cipher = RC6()
        bin_massage = cipher.bytesToBin(message)
        bin_key = cipher.bytesToBin(key)
        encryption_bin_message = cipher.encryption(bin_massage, bin_key)
        out.write(cipher.binToBytes(encryption_bin_message))
        inp.close()
        out.close()

    def decryptImage(self, inputImagePath, outputImagePath, key):
        inp = open(inputImagePath, "rb")
        out = open(outputImagePath, "wb")
        message = inp.read()
        key = base64.b64encode(bytes(key, "utf-8"))
        cipher = RC6()
        bin_key = cipher.bytesToBin(key)
        message = cipher.bytesToBin(message)
        decryption_bin_message = cipher.decryption(message, bin_key)
        decryption_message = cipher.binToBytes(decryption_bin_message)
        out.write(base64.b64decode(decryption_message))
        inp.close()
        out.close()


# inp = open("testImage2.png", "rb")
# message = inp.read()
# message = base64.b64encode(message)
# key = base64.b64encode(bytes("""Secret key""", "utf-8"))

# cipher = RC6()
# bin_massage = cipher.bytesToBin(message)
# bin_key = cipher.bytesToBin(key)

# encryption_bin_message = cipher.encryption(bin_massage, bin_key)
# decryption_bin_message = cipher.decryption(encryption_bin_message, bin_key)
# decryption_message = cipher.binToBytes(decryption_bin_message)

# out = open("output.png", "wb")
# out.write(base64.b64decode(decryption_message))

# print("MESSAGE:", base64.b64decode(message))
# print("KEY:", base64.b64decode(key), "\n")
# print("BIN MESSAGE:", bin_massage, "\n")
# print("ENCRYPTION BIN MESSAGE:", encryption_bin_message, "\n")
# print("DECRYPTION BIN MESSAGE:", decryption_bin_message, "\n")
# print("DECRYPTION MESSAGE:", base64.b64decode(decryption_message))

