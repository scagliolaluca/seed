"""passlib.handlers.pbkdf - PBKDF2 based hashes"""
#=============================================================================
# imports
#=============================================================================
# core
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
import logging; log = logging.getLogger(__name__)
# site
# pkg
from lib.passlib.utils import to_unicode
from lib.passlib.utils.binary import ab64_decode, ab64_encode
from lib.passlib.utils.compat import str_to_bascii, u, uascii_to_str, unicode
from lib.passlib.crypto.digest import pbkdf2_hmac
import lib.passlib.utils.handlers as uh
# local
__all__ = [
    "pbkdf2_sha1",
    "pbkdf2_sha256",
    "pbkdf2_sha512",
    "cta_pbkdf2_sha1",
    "dlitz_pbkdf2_sha1",
    "grub_pbkdf2_sha512",
]

#=============================================================================
#
#=============================================================================
class Pbkdf2DigestHandler(uh.HasRounds, uh.HasRawSalt, uh.HasRawChecksum, uh.GenericHandler):
    """base class for various pbkdf2_{digest} algorithms"""
    #===================================================================
    # class attrs
    #===================================================================

    #--GenericHandler--
    setting_kwds = ("salt", "salt_size", "rounds")
    checksum_chars = uh.HASH64_CHARS

    #--HasSalt--
    default_salt_size = 16
    max_salt_size = 1024

    #--HasRounds--
    default_rounds = None # set by subclass
    min_rounds = 1
    max_rounds = 0xffffffff # setting at 32-bit limit for now
    rounds_cost = "linear"

    #--this class--
    _digest = None # name of subclass-specified hash

    # NOTE: max_salt_size and max_rounds are arbitrarily chosen to provide sanity check.
    #       the underlying pbkdf2 specifies no bounds for either.

    # NOTE: defaults chosen to be at least as large as pbkdf2 rfc recommends...
    #       >8 bytes of entropy in salt, >1000 rounds
    #       increased due to time since rfc established

    #===================================================================
    # methods
    #===================================================================

    @classmethod
    def from_string(cls, hash):
        rounds, salt, chk = uh.parse_mc3(hash, cls.ident, handler=cls)
        salt = ab64_decode(salt.encode("ascii"))
        if chk:
            chk = ab64_decode(chk.encode("ascii"))
        return cls(rounds=rounds, salt=salt, checksum=chk)

    def to_string(self):
        salt = ab64_encode(self.salt).decode("ascii")
        chk = ab64_encode(self.checksum).decode("ascii")
        return uh.render_mc3(self.ident, self.rounds, salt, chk)

    def _calc_checksum(self, secret):
        # NOTE: pbkdf2_hmac() will encode secret & salt using UTF8
        return pbkdf2_hmac(self._digest, secret, self.salt, self.rounds, self.checksum_size)

def create_pbkdf2_hash(hash_name, digest_size, rounds=12000, ident=None, module=__name__):
    """create new Pbkdf2DigestHandler subclass for a specific hash"""
    name = 'pbkdf2_' + hash_name
    if ident is None:
        ident = u("$pbkdf2-%s$") % (hash_name,)
    base = Pbkdf2DigestHandler
    return type(name, (base,), dict(
        __module__=module, # so ABCMeta won't clobber it.
        name=name,
        ident=ident,
        _digest = hash_name,
        default_rounds=rounds,
        checksum_size=digest_size,
        encoded_checksum_size=(digest_size*4+2)//3,
        __doc__="""This class implements a generic ``PBKDF2-HMAC-%(digest)s``-based password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, and a variable number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: bytes
    :param salt:
        Optional salt bytes.
        If specified, the length must be between 0-1024 bytes.
        If not specified, a %(dsc)d byte salt will be autogenerated (this is recommended).

    :type salt_size: int
    :param salt_size:
        Optional number of bytes to use when autogenerating new salts.
        Defaults to %(dsc)d bytes, but can be any value between 0 and 1024.

    :type rounds: int
    :param rounds:
        Optional number of rounds to use.
        Defaults to %(dr)d, but must be within ``range(1,1<<32)``.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include ``rounds``
        that are too small or too large, and ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """ % dict(digest=hash_name.upper(), dsc=base.default_salt_size, dr=rounds)
    ))

#------------------------------------------------------------------------
# derived handlers
#------------------------------------------------------------------------
pbkdf2_sha1 = create_pbkdf2_hash("sha1", 20, 131000, ident=u("$pbkdf2$"))
pbkdf2_sha256 = create_pbkdf2_hash("sha256", 32, 29000)
pbkdf2_sha512 = create_pbkdf2_hash("sha512", 64, 25000)

ldap_pbkdf2_sha1 = uh.PrefixWrapper("ldap_pbkdf2_sha1", pbkdf2_sha1, "{PBKDF2}", "$pbkdf2$", ident=True)
ldap_pbkdf2_sha256 = uh.PrefixWrapper("ldap_pbkdf2_sha256", pbkdf2_sha256, "{PBKDF2-SHA256}", "$pbkdf2-sha256$", ident=True)
ldap_pbkdf2_sha512 = uh.PrefixWrapper("ldap_pbkdf2_sha512", pbkdf2_sha512, "{PBKDF2-SHA512}", "$pbkdf2-sha512$", ident=True)

#=============================================================================
# cryptacular's pbkdf2 hash
#=============================================================================

# bytes used by cta hash for base64 values 63 & 64
CTA_ALTCHARS = b"-_"

class cta_pbkdf2_sha1(uh.HasRounds, uh.HasRawSalt, uh.HasRawChecksum, uh.GenericHandler):
    """This class implements Cryptacular's PBKDF2-based crypt algorithm, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, and a variable number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: bytes
    :param salt:
        Optional salt bytes.
        If specified, it may be any length.
        If not specified, a one will be autogenerated (this is recommended).

    :type salt_size: int
    :param salt_size:
        Optional number of bytes to use when autogenerating new salts.
        Defaults to 16 bytes, but can be any value between 0 and 1024.

    :type rounds: int
    :param rounds:
        Optional number of rounds to use.
        Defaults to 60000, must be within ``range(1,1<<32)``.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include ``rounds``
        that are too small or too large, and ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    #===================================================================
    # class attrs
    #===================================================================
    #--GenericHandler--
    name = "cta_pbkdf2_sha1"
    setting_kwds = ("salt", "salt_size", "rounds")
    ident = u("$p5k2$")
    checksum_size = 20

    # NOTE: max_salt_size and max_rounds are arbitrarily chosen to provide a
    #       sanity check. underlying algorithm (and reference implementation)
    #       allows effectively unbounded values for both of these parameters.

    #--HasSalt--
    default_salt_size = 16
    max_salt_size = 1024

    #--HasRounds--
    default_rounds = pbkdf2_sha1.default_rounds
    min_rounds = 1
    max_rounds = 0xffffffff # setting at 32-bit limit for now
    rounds_cost = "linear"

    #===================================================================
    # formatting
    #===================================================================

    # hash       $p5k2$1000$ZxK4ZBJCfQg=$jJZVscWtO--p1-xIZl6jhO2LKR0=
    # ident      $p5k2$
    # rounds     1000
    # salt       ZxK4ZBJCfQg=
    # chk        jJZVscWtO--p1-xIZl6jhO2LKR0=
    # NOTE: rounds in hex

    @classmethod
    def from_string(cls, hash):
        # NOTE: passlib deviation - forbidding zero-padded rounds
        rounds, salt, chk = uh.parse_mc3(hash, cls.ident, rounds_base=16, handler=cls)
        salt = b64decode(salt.encode("ascii"), CTA_ALTCHARS)
        if chk:
            chk = b64decode(chk.encode("ascii"), CTA_ALTCHARS)
        return cls(rounds=rounds, salt=salt, checksum=chk)

    def to_string(self):
        salt = b64encode(self.salt, CTA_ALTCHARS).decode("ascii")
        chk = b64encode(self.checksum, CTA_ALTCHARS).decode("ascii")
        return uh.render_mc3(self.ident, self.rounds, salt, chk, rounds_base=16)

    #===================================================================
    # backend
    #===================================================================
    def _calc_checksum(self, secret):
        # NOTE: pbkdf2_hmac() will encode secret & salt using utf-8
        return pbkdf2_hmac("sha1", secret, self.salt, self.rounds, 20)

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# dlitz's pbkdf2 hash
#=============================================================================
class dlitz_pbkdf2_sha1(uh.HasRounds, uh.HasSalt, uh.GenericHandler):
    """This class implements Dwayne Litzenberger's PBKDF2-based crypt algorithm, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, and a variable number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If specified, it may be any length, but must use the characters in the regexp range ``[./0-9A-Za-z]``.
        If not specified, a 16 character salt will be autogenerated (this is recommended).

    :type salt_size: int
    :param salt_size:
        Optional number of bytes to use when autogenerating new salts.
        Defaults to 16 bytes, but can be any value between 0 and 1024.

    :type rounds: int
    :param rounds:
        Optional number of rounds to use.
        Defaults to 60000, must be within ``range(1,1<<32)``.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include ``rounds``
        that are too small or too large, and ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    #===================================================================
    # class attrs
    #===================================================================
    #--GenericHandler--
    name = "dlitz_pbkdf2_sha1"
    setting_kwds = ("salt", "salt_size", "rounds")
    ident = u("$p5k2$")
    _stub_checksum = u("0" * 48 + "=")

    # NOTE: max_salt_size and max_rounds are arbitrarily chosen to provide a
    #       sanity check. underlying algorithm (and reference implementation)
    #       allows effectively unbounded values for both of these parameters.

    #--HasSalt--
    default_salt_size = 16
    max_salt_size = 1024
    salt_chars = uh.HASH64_CHARS

    #--HasRounds--
    # NOTE: for security, the default here is set to match pbkdf2_sha1,
    #       even though this hash's extra block makes it twice as slow.
    default_rounds = pbkdf2_sha1.default_rounds
    min_rounds = 1
    max_rounds = 0xffffffff # setting at 32-bit limit for now
    rounds_cost = "linear"

    #===================================================================
    # formatting
    #===================================================================

    # hash       $p5k2$c$u9HvcT4d$Sd1gwSVCLZYAuqZ25piRnbBEoAesaa/g
    # ident      $p5k2$
    # rounds     c
    # salt       u9HvcT4d
    # chk        Sd1gwSVCLZYAuqZ25piRnbBEoAesaa/g
    # rounds in lowercase hex, no zero padding

    @classmethod
    def from_string(cls, hash):
        rounds, salt, chk = uh.parse_mc3(hash, cls.ident, rounds_base=16,
                                         default_rounds=400, handler=cls)
        return cls(rounds=rounds, salt=salt, checksum=chk)

    def to_string(self):
        rounds = self.rounds
        if rounds == 400:
            rounds = None # omit rounds measurement if == 400
        return uh.render_mc3(self.ident, rounds, self.salt, self.checksum, rounds_base=16)

    def _get_config(self):
        rounds = self.rounds
        if rounds == 400:
            rounds = None # omit rounds measurement if == 400
        return uh.render_mc3(self.ident, rounds, self.salt, None, rounds_base=16)

    #===================================================================
    # backend
    #===================================================================
    def _calc_checksum(self, secret):
        # NOTE: pbkdf2_hmac() will encode secret & salt using utf-8
        salt = self._get_config()
        result = pbkdf2_hmac("sha1", secret, salt, self.rounds, 24)
        return ab64_encode(result).decode("ascii")

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# crowd
#=============================================================================
class atlassian_pbkdf2_sha1(uh.HasRawSalt, uh.HasRawChecksum, uh.GenericHandler):
    """This class implements the PBKDF2 hash used by Atlassian.

    It supports a fixed-length salt, and a fixed number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: bytes
    :param salt:
        Optional salt bytes.
        If specified, the length must be exactly 16 bytes.
        If not specified, a salt will be autogenerated (this is recommended).

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include
        ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """
    #--GenericHandler--
    name = "atlassian_pbkdf2_sha1"
    setting_kwds =("salt",)
    ident = u("{PKCS5S2}")
    checksum_size = 32

    #--HasRawSalt--
    min_salt_size = max_salt_size = 16

    @classmethod
    def from_string(cls, hash):
        hash = to_unicode(hash, "ascii", "hash")
        ident = cls.ident
        if not hash.startswith(ident):
            raise uh.exc.InvalidHashError(cls)
        data = b64decode(hash[len(ident):].encode("ascii"))
        salt, chk = data[:16], data[16:]
        return cls(salt=salt, checksum=chk)

    def to_string(self):
        data = self.salt + self.checksum
        hash = self.ident + b64encode(data).decode("ascii")
        return uascii_to_str(hash)

    def _calc_checksum(self, secret):
        # TODO: find out what crowd's policy is re: unicode
        # crowd seems to use a fixed number of rounds.
        # NOTE: pbkdf2_hmac() will encode secret & salt using utf-8
        return pbkdf2_hmac("sha1", secret, self.salt, 10000, 32)

#=============================================================================
# grub
#=============================================================================
class grub_pbkdf2_sha512(uh.HasRounds, uh.HasRawSalt, uh.HasRawChecksum, uh.GenericHandler):
    """This class implements Grub's pbkdf2-hmac-sha512 hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, and a variable number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: bytes
    :param salt:
        Optional salt bytes.
        If specified, the length must be between 0-1024 bytes.
        If not specified, a 64 byte salt will be autogenerated (this is recommended).

    :type salt_size: int
    :param salt_size:
        Optional number of bytes to use when autogenerating new salts.
        Defaults to 64 bytes, but can be any value between 0 and 1024.

    :type rounds: int
    :param rounds:
        Optional number of rounds to use.
        Defaults to 19000, but must be within ``range(1,1<<32)``.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include ``rounds``
        that are too small or too large, and ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """
    name = "grub_pbkdf2_sha512"
    setting_kwds = ("salt", "salt_size", "rounds")

    ident = u("grub.pbkdf2.sha512.")
    checksum_size = 64

    # NOTE: max_salt_size and max_rounds are arbitrarily chosen to provide a
    #       sanity check. the underlying pbkdf2 specifies no bounds for either,
    #       and it's not clear what grub specifies.

    default_salt_size = 64
    max_salt_size = 1024

    default_rounds = pbkdf2_sha512.default_rounds
    min_rounds = 1
    max_rounds = 0xffffffff # setting at 32-bit limit for now
    rounds_cost = "linear"

    @classmethod
    def from_string(cls, hash):
        rounds, salt, chk = uh.parse_mc3(hash, cls.ident, sep=u("."),
                                         handler=cls)
        salt = unhexlify(salt.encode("ascii"))
        if chk:
            chk = unhexlify(chk.encode("ascii"))
        return cls(rounds=rounds, salt=salt, checksum=chk)

    def to_string(self):
        salt = hexlify(self.salt).decode("ascii").upper()
        chk = hexlify(self.checksum).decode("ascii").upper()
        return uh.render_mc3(self.ident, self.rounds, salt, chk, sep=u("."))

    def _calc_checksum(self, secret):
        # TODO: find out what grub's policy is re: unicode
        # NOTE: pbkdf2_hmac() will encode secret & salt using utf-8
        return pbkdf2_hmac("sha512", secret, self.salt, self.rounds, 64)

#=============================================================================
# eof
#=============================================================================
