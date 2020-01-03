l = 7237005577332262213973186563042994240857116359379907606001950938285454250989
G = Integers(l)


class AddGadget(object):
    def __init__(self):
        self.ctr = 0

    def add(self, x, y):
        self.ctr += 1
        return x + y


ADDER = AddGadget()
ADD = ADDER.add

a = G.random_element()
base = [a]
while len(base) < 256:
    base.append(ADD(base[-1], base[-1]))

acc = [base[i] for i in range(256) if (l & 2**i) > 0]

print('Base size: %s' % len(acc))
zero = reduce(lambda x, y: ADD(x, y), acc)

print('Correctness: %s, additions: %s' % (zero, ADDER.ctr))

# Enc oracle:
for i in range(100):
    x = G.random_element()
    z = (a^-1) * x
    acc = [base[i] for i in range(256) if (int(z) & 2**i) > 0]
    xx = sum(acc)
    if x-xx != 0:
        raise ValueError('Error in enc oracle for a: %s' % x)


