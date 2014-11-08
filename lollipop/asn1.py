import hashlib
from pyasn1.type import (
    constraint,
    univ,
    namedtype,
    namedval,
    tag,
)

OID = dict(
    EC_PUBLIC_KEY = '1.2.840.10045.2.1',
    SECP256K1     = '1.3.132.0.10',
)
OID_HASH = {
    hashlib.sha1: b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
}


class DSAPrivateKey(univ.Sequence):
    '''
    DSAPrivateKey ::= SEQUENCE {
        version          INTEGER,
        p                INTEGER,
        q                INTEGER,
        g                INTEGER,
        pub_key          INTEGER,
        priv_key         INTEGER
    }
    '''
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(
            namedValues=namedval.NamedValues(('v1', 0))
        )),
        namedtype.NamedType('p', univ.Integer()),
        namedtype.NamedType('q', univ.Integer()),
        namedtype.NamedType('g', univ.Integer()),
        namedtype.NamedType('public', univ.Integer()),
        namedtype.NamedType('private', univ.Integer()),
    )


class ECPrivateKey(univ.Sequence):
    '''
    ECPrivateKey ::= SEQUENCE {
        version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        privateKey     OCTET STRING,
        parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        publicKey  [1] BIT STRING OPTIONAL
    }
    '''
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('privateKey', univ.OctetString()),
        namedtype.NamedType('namedCurve', univ.ObjectIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        namedtype.NamedType('publicKey', univ.BitString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )),
    )


class OtherPrimeInfo(univ.Sequence):
    '''
    OtherPrimeInfo ::= SEQUENCE {
        prime             INTEGER,  -- ri
        exponent          INTEGER,  -- di
        coefficient       INTEGER   -- ti
    }
    '''
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('prime', univ.Integer()),
        namedtype.NamedType('exponent', univ.Integer()),
        namedtype.NamedType('coefficient', univ.Integer()),
    )


class OtherPrimeInfos(univ.SequenceOf):
    '''
    OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
    '''
    componentType = OtherPrimeInfo()
    subtypeSpec = univ.SequenceOf.subtypeSpec + \
                  constraint.ValueSizeConstraint(1, 16)


class RSAPrivateKey(univ.Sequence):
    '''
    RSAPrivateKey ::= SEQUENCE {
        version           Version,
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e
        privateExponent   INTEGER,  -- d
        prime1            INTEGER,  -- p
        prime2            INTEGER,  -- q
        exponent1         INTEGER,  -- d mod (p-1)
        exponent2         INTEGER,  -- d mod (q-1)
        coefficient       INTEGER,  -- (inverse of q) mod p
        otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }
    '''

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(
            namedValues=namedval.NamedValues(
                ('two-prime', 0),
                ('multi', 1)
            )
        )),
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer()),
        namedtype.NamedType('privateExponent', univ.Integer()),
        namedtype.NamedType('prime1', univ.Integer()),
        namedtype.NamedType('prime2', univ.Integer()),
        namedtype.NamedType('exponent1', univ.Integer()),
        namedtype.NamedType('exponent2', univ.Integer()),
        namedtype.NamedType('coefficient', univ.Integer()),
        namedtype.OptionalNamedType('otherPrimeInfos', OtherPrimeInfos()),
    )
