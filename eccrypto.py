import os
import hashlib
import struct


def int_to_bytes(raw, length):
    data = []
    for _ in range(length):
        data.append(raw % 256)
        raw //= 256
    return bytes(data[::-1])


def bytes_to_int(data):
    raw = 0
    for byte in data:
        raw = raw * 256 + byte
    return raw


def legendre(a, p):
    res = pow(a, (p - 1) // 2, p)
    if res == p - 1:
        return -1
    else:
        return res


def inverse(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def square_root_mod_prime(n, p):
    if n == 0:
        return 0
    if p == 2:
        return n  # We should never get here but it might be useful
    if legendre(n, p) != 1:
        raise ValueError("No square root")
    # Optimizations
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    # 1. By factoring out powers of 2, find Q and S such that p - 1 =
    # Q * 2 ** S with Q odd
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    # 2. Search for z in Z/pZ which is a quadratic non-residue
    z = 1
    while legendre(z, p) != -1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while True:
        if t == 0:
            return 0
        elif t == 1:
            return r
        # Use repeated squaring to find the least i, 0 < i < M, such
        # that t ** (2 ** i) = 1
        t_sq = t
        i = 0
        for i in range(1, m):
            t_sq = t_sq * t_sq % p
            if t_sq == 1:
                break
        else:
            raise ValueError("Should never get here")
        # Let b = c ** (2 ** (m - i - 1))
        b = pow(c, 2**(m - i - 1), p)
        m = i
        c = b * b % p
        t = t * b * b % p
        r = r * b % p
    return r


class JacobianCurve:
    def __init__(self, p, n, a, b, g):
        self.p = p
        self.n = n
        self.a = a
        self.b = b
        self.g = g
        self.n_length = len(bin(self.n).replace("0b", ""))

    def isinf(self, p):
        return p[0] == 0 and p[1] == 0

    def to_jacobian(self, p):
        return p[0], p[1], 1

    def jacobian_double(self, p):
        if not p[1]:
            return 0, 0, 0
        ysq = (p[1]**2) % self.p
        s = (4 * p[0] * ysq) % self.p
        m = (3 * p[0]**2 + self.a * p[2]**4) % self.p
        nx = (m**2 - 2 * s) % self.p
        ny = (m * (s - nx) - 8 * ysq**2) % self.p
        nz = (2 * p[1] * p[2]) % self.p
        return nx, ny, nz

    def jacobian_add(self, p, q):
        if not p[1]:
            return q
        if not q[1]:
            return p
        u1 = (p[0] * q[2]**2) % self.p
        u2 = (q[0] * p[2]**2) % self.p
        s1 = (p[1] * q[2]**3) % self.p
        s2 = (q[1] * p[2]**3) % self.p
        if u1 == u2:
            if s1 != s2:
                return (0, 0, 1)
            return self.jacobian_double(p)
        h = u2 - u1
        r = s2 - s1
        h2 = (h * h) % self.p
        h3 = (h * h2) % self.p
        u1h2 = (u1 * h2) % self.p
        nx = (r**2 - h3 - 2 * u1h2) % self.p
        ny = (r * (u1h2 - nx) - s1 * h3) % self.p
        nz = (h * p[2] * q[2]) % self.p
        return (nx, ny, nz)

    def from_jacobian(self, p):
        z = inverse(p[2], self.p)
        return (p[0] * z**2) % self.p, (p[1] * z**3) % self.p

    def jacobian_multiply(self, a, n, secret=False):
        if a[1] == 0 or n == 0:
            return 0, 0, 1
        if n == 1:
            return a
        if n < 0 or n >= self.n:
            return self.jacobian_multiply(a, n % self.n, secret)
        half = self.jacobian_multiply(a, n // 2, secret)
        half_sq = self.jacobian_double(half)
        if secret:
            # A constant-time implementation
            half_sq_a = self.jacobian_add(half_sq, a)
            if n % 2 == 0:
                result = half_sq
            if n % 2 == 1:
                result = half_sq_a
            return result
        else:
            if n % 2 == 0:
                return half_sq
            return self.jacobian_add(half_sq, a)

    def fast_multiply(self, a, n, secret=False):
        return self.from_jacobian(
            self.jacobian_multiply(self.to_jacobian(a), n, secret))


class EllipticCurveBackend:
    def __init__(self, p, n, a, b, g):
        self.p, self.n, self.a, self.b, self.g = p, n, a, b, g
        self.jacobian = JacobianCurve(p, n, a, b, g)

        self.public_key_length = (len(bin(p).replace("0b", "")) + 7) // 8
        self.order_bitlength = len(bin(n).replace("0b", ""))

    def _int_to_bytes(self, raw, len=None):
        return int_to_bytes(raw, len or self.public_key_length)

    def decompress_point(self, public_key):
        # Parse & load data
        x = bytes_to_int(public_key[1:])
        # Calculate Y
        y_square = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        try:
            y = square_root_mod_prime(y_square, self.p)
        except Exception:
            raise ValueError("Invalid public key") from None
        if y % 2 != public_key[0] - 0x02:
            y = self.p - y
        return self._int_to_bytes(x), self._int_to_bytes(y)

    def new_private_key(self):
        while True:
            private_key = os.urandom(self.public_key_length)
            if bytes_to_int(private_key) >= self.n:
                continue
            return private_key

    def private_to_public(self, private_key):
        raw = bytes_to_int(private_key)
        x, y = self.jacobian.fast_multiply(self.g, raw)
        return self._int_to_bytes(x), self._int_to_bytes(y)

    def ecdh(self, private_key, public_key):
        x, y = public_key
        x, y = bytes_to_int(x), bytes_to_int(y)
        private_key = bytes_to_int(private_key)
        x, _ = self.jacobian.fast_multiply((x, y), private_key, secret=True)
        return self._int_to_bytes(x)

    def _subject_to_int(self, subject):
        return bytes_to_int(subject[:(self.order_bitlength + 7) // 8])


class ECC:
    # pylint: disable=line-too-long
    # name: (nid, p, n, a, b, (Gx, Gy)),
    CURVE = (
        714,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141, 0,
        7,
        (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8))

    # pylint: enable=line-too-long

    def __init__(self, backend, aes):
        self._backend = backend
        self._aes = aes

    def get_curve(self):
        nid, p, n, a, b, g = self.CURVE
        params = {"p": p, "n": n, "a": a, "b": b, "g": g}
        return EllipticCurve(self._backend, params, self._aes, nid)


class EllipticCurve:
    def __init__(self, backend_factory, params, aes, nid):
        self._backend = backend_factory(**params)
        self.params = params
        self._aes = aes
        self.nid = nid

    def _encode_public_key(self, x, y, is_compressed=True, raw=True):
        if raw:
            if is_compressed:
                return bytes([0x02 + (y[-1] % 2)]) + x
            else:
                return bytes([0x04]) + x + y
        else:
            return struct.pack("!HH", self.nid, len(x)) + x + struct.pack(
                "!H", len(y)) + y

    def _decode_public_key(self, public_key, partial=False):
        if not public_key:
            raise ValueError("No public key")

        if public_key[0] == 0x04:
            # Uncompressed
            expected_length = 1 + 2 * self._backend.public_key_length
            if partial:
                if len(public_key) < expected_length:
                    raise ValueError("Invalid uncompressed public key length")
            else:
                if len(public_key) != expected_length:
                    raise ValueError("Invalid uncompressed public key length")
            x = public_key[1:1 + self._backend.public_key_length]
            y = public_key[1 + self._backend.public_key_length:expected_length]
            if partial:
                return (x, y), expected_length
            else:
                return x, y
        elif public_key[0] in (0x02, 0x03):
            # Compressed
            expected_length = 1 + self._backend.public_key_length
            if partial:
                if len(public_key) < expected_length:
                    raise ValueError("Invalid compressed public key length")
            else:
                if len(public_key) != expected_length:
                    raise ValueError("Invalid compressed public key length")

            x, y = self._backend.decompress_point(public_key[:expected_length])
            # Sanity check
            if x != public_key[1:expected_length]:
                raise ValueError("Incorrect compressed public key")
            if partial:
                return (x, y), expected_length
            else:
                return x, y
        else:
            raise ValueError("Invalid public key prefix")

    def decode_public_key(self, public_key):
        return self._decode_public_key(public_key)

    def new_private_key(self, is_compressed=False):
        return self._backend.new_private_key() + (b"\x01"
                                                  if is_compressed else b"")

    def private_to_public(self, private_key):
        if len(private_key) == self._backend.public_key_length:
            is_compressed = False
        elif len(
                private_key
        ) == self._backend.public_key_length + 1 and private_key[-1] == 1:
            is_compressed = True
            private_key = private_key[:-1]
        else:
            raise ValueError("Private key has invalid length")
        x, y = self._backend.private_to_public(private_key)
        return self._encode_public_key(x, y, is_compressed=is_compressed)

    def _digest(self, data, hash):
        if hash is None:
            return data
        elif callable(hash):
            return hash(data)
        elif hash == "sha1":
            return hashlib.sha1(data).digest()
        elif hash == "sha256":
            return hashlib.sha256(data).digest()
        elif hash == "sha512":
            return hashlib.sha512(data).digest()
        else:
            raise ValueError("Unknown hash/derivation method")


ecc = ECC(EllipticCurveBackend, None)
curve = ecc.get_curve()
