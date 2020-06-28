{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Include
module Crypto.Fido2.PublicKey
  ( COSEAlgorithmIdentifier (..),
    ECDSAIdentifier (..),
    PublicKey,
    decodePublicKey,
    encodePublicKey,
    verify,
  )
where

import qualified Codec.CBOR.Decoding as CBOR
import Codec.CBOR.Decoding (Decoder)
import qualified Codec.CBOR.Encoding as CBOR
import Codec.CBOR.Encoding (Encoding)
import Control.Monad (when)
import Crypto.Error (CryptoFailable (CryptoFailed, CryptoPassed))
import qualified Crypto.Hash.Algorithms as Hash
import Crypto.Number.Serialize (i2osp, os2ip)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import Crypto.Random (drgNewSeed, seedFromInteger, withDRG)
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Prim as ASN1
import Data.Aeson.Types (ToJSON (toJSON))
import qualified Data.Aeson.Types as Aeson
import qualified Data.ByteArray as ByteArray
import Data.ByteString (ByteString)
import Test.QuickCheck (Arbitrary, Gen, arbitrary, elements, oneof)

data ECDSAIdentifier
  = ES256
  | ES384
  | ES512
  deriving (Show, Eq)

instance Arbitrary ECDSAIdentifier where
  arbitrary = elements [ES256, ES384, ES512]

data COSEAlgorithmIdentifier
  = ECDSAIdentifier ECDSAIdentifier
  | EdDSA
  deriving (Show, Eq)

instance Arbitrary COSEAlgorithmIdentifier where
  arbitrary = oneof [pure EdDSA, arbitrary]

-- All CBOR is encoded using
-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#ctap2-canonical-cbor-encoding-form

--
-- a signature decoding uniquely belongs to an algorithm identifier. how do we
-- encode this correspondence?
decodeCOSEAlgorithmIdentifier :: Decoder s COSEAlgorithmIdentifier
decodeCOSEAlgorithmIdentifier =
  toAlg =<< CBOR.decodeIntCanonical
  where
    toAlg (-7) = pure $ ECDSAIdentifier ES256
    toAlg (-35) = pure $ ECDSAIdentifier ES384
    toAlg (-36) = pure $ ECDSAIdentifier ES512
    toAlg (-8) = pure EdDSA
    toAlg _ = fail "Unsupported `alg`"

instance ToJSON COSEAlgorithmIdentifier where
  toJSON (ECDSAIdentifier ES256) = Aeson.Number (-7)
  toJSON (ECDSAIdentifier ES384) = Aeson.Number (-35)
  toJSON (ECDSAIdentifier ES512) = Aeson.Number (-36)
  toJSON EdDSA = Aeson.Number (-8)

data EdDSAKey
  = Ed25519 Ed25519.PublicKey
  | Ed448 Ed448.PublicKey
  deriving (Eq, Show)

instance Arbitrary EdDSAKey where
  arbitrary =
    oneof
      [ Ed25519 <$> randomEd25519PublicKey,
        Ed448 <$> randomEd448PublicKey
      ]

randomEd25519PublicKey :: Gen Ed25519.PublicKey
randomEd25519PublicKey = do
  rng <- drgNewSeed . seedFromInteger <$> arbitrary
  let (a, _) = withDRG rng (Ed25519.toPublic <$> Ed25519.generateSecretKey)
  pure a

randomEd448PublicKey :: Gen Ed448.PublicKey
randomEd448PublicKey = do
  rng <- drgNewSeed . seedFromInteger <$> arbitrary
  let (a, _) = withDRG rng (Ed448.toPublic <$> Ed448.generateSecretKey)
  pure a

randomECDSAPublicKey :: Gen (CurveIdentifier, ECC.Point)
randomECDSAPublicKey = do
  curveIdentifier <- arbitrary
  let curve = toCurve curveIdentifier
  rng <- drgNewSeed . seedFromInteger <$> arbitrary
  let ((ECDSA.PublicKey _ point, _), _) = withDRG rng (ECC.generate curve)
  pure (curveIdentifier, point)

-- Curves supported by us
data CurveIdentifier = P256 | P384 | P521 deriving (Eq, Show)

instance Arbitrary CurveIdentifier where
  arbitrary = elements [P256, P384, P521]

toCurve :: CurveIdentifier -> ECC.Curve
toCurve P256 = ECC.getCurveByName ECC.SEC_p256r1
toCurve P384 = ECC.getCurveByName ECC.SEC_p384r1
toCurve P521 = ECC.getCurveByName ECC.SEC_p521r1

data ECDSAKey = ECDSAKey ECDSAIdentifier CurveIdentifier ECC.Point deriving (Eq, Show)

instance Arbitrary ECDSAKey where
  arbitrary =
    oneof
      [ uncurry (ECDSAKey ES256) <$> randomECDSAPublicKey,
        uncurry (ECDSAKey ES384) <$> randomECDSAPublicKey,
        uncurry (ECDSAKey ES512) <$> randomECDSAPublicKey
      ]

data PublicKey
  = EdDSAPublicKey EdDSAKey
  | ECDSAPublicKey ECDSAKey
  deriving (Show, Eq)

instance Arbitrary PublicKey where
  arbitrary = oneof [EdDSAPublicKey <$> arbitrary, ECDSAPublicKey <$> arbitrary]

-- | The credential public key encoded in COSE_Key format, as defined in Section 7
-- of [RFC8152], using the CTAP2 canonical CBOR encoding form. The
-- COSE_Key-encoded credential public key MUST contain the "alg" parameter and
-- MUST NOT contain any other OPTIONAL parameters. The "alg" parameter MUST
-- contain a COSEAlgorithmIdentifier value. The encoded credential public key
-- MUST also contain any additional REQUIRED parameters stipulated by the
-- relevant key type specification, i.e., REQUIRED for the key type "kty" and
-- algorithm "alg" (see Section 8 of [RFC8152]).
--
-- Furthermore: CBOR values are CTAP2 canonical encoded.
-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#ctap2-canonical-cbor-encoding-form
decodePublicKey :: Decoder s PublicKey
decodePublicKey = do
  _n <- CBOR.decodeMapLenCanonical
  ktyKey <- CBOR.decodeIntCanonical
  when (ktyKey /= 1) $ fail "Expected required `kty`"
  kty <- CBOR.decodeIntCanonical
  case kty of
    1 -> EdDSAPublicKey <$> decodeEdDSAKey
    2 -> ECDSAPublicKey <$> decodeECDSAPublicKey
    x -> fail $ "unexpected kty: " ++ show x

decodeEdDSAKey :: Decoder s EdDSAKey
decodeEdDSAKey = do
  algKey <- CBOR.decodeIntCanonical
  when (algKey /= 3) $ fail "Expected required `alg`"
  alg <- decodeCOSEAlgorithmIdentifier
  when (alg /= EdDSA) $ fail "Unsupported `alg`"
  crvKey <- CBOR.decodeIntCanonical
  when (crvKey /= (-1)) $ fail "Expected required `crv`"
  crv <- CBOR.decodeIntCanonical
  xKey <- CBOR.decodeIntCanonical
  when (xKey /= -2) $ fail "Expected required `x`"
  x <- CBOR.decodeBytesCanonical
  case crv of
    6 ->
      case Ed25519.publicKey x of
        CryptoFailed e -> fail (show e)
        CryptoPassed a -> pure $ Ed25519 a
    7 ->
      case Ed448.publicKey x of
        CryptoFailed e -> fail (show e)
        CryptoPassed a -> pure $ Ed448 a
    _ -> fail "Unsupported `crv`"

decodeECDSAPublicKey :: Decoder s ECDSAKey
decodeECDSAPublicKey = do
  algKey <- CBOR.decodeIntCanonical
  when (algKey /= 3) $ fail "Expected required `alg`"
  alg <- decodeCOSEAlgorithmIdentifier
  hash <- case alg of
    ECDSAIdentifier x -> pure x
    _ -> fail "Unsupported `alg`"
  crvKey <- CBOR.decodeIntCanonical
  when (crvKey /= (-1)) $ fail "Expected required `crv`"
  crv <- CBOR.decodeIntCanonical
  curve <- case crv of
    1 -> pure $ P256
    2 -> pure $ P384
    3 -> pure $ P521
    _ -> fail "Unsupported `crv`"
  xKey <- CBOR.decodeIntCanonical
  when (xKey /= -2) $ fail "Expected required `x`"
  x <- os2ip <$> CBOR.decodeBytesCanonical
  yKey <- CBOR.decodeIntCanonical
  when (yKey /= -3) $ fail "Expected required `x`"
  tokenType <- CBOR.peekTokenType
  y <- case tokenType of
    -- TODO(arianvp): Implement compressed curve. Waiting for
    -- https://github.com/haskell-crypto/cryptonite/issues/302
    CBOR.TypeBool -> fail "Compressed format not supported _yet_ See Issue number X"
    -- direct coordinate
    CBOR.TypeBytes -> os2ip <$> CBOR.decodeBytesCanonical
    _ -> fail "Unexpected token type"
  let point = ECC.Point x y
  when (not (ECC.isPointValid (toCurve curve) point)) $ fail "point not on curve"
  pure $ ECDSAKey hash curve (ECC.Point x y)

encodePublicKey :: PublicKey -> Encoding
encodePublicKey (ECDSAPublicKey (ECDSAKey alg curve point)) =
  CBOR.encodeMapLen 5
    <> CBOR.encodeInt 1
    <> CBOR.encodeInt 2
    <> CBOR.encodeInt 3
    <> encodeCOSEAlgorithmIdentifier (ECDSAIdentifier alg)
    <> CBOR.encodeInt (-1)
    <> CBOR.encodeInt
      ( case curve of
          P256 -> 1
          P384 -> 2
          P521 -> 3
      )
    <> ( case point of
           ECC.Point x y ->
             CBOR.encodeInt (-2)
               <> CBOR.encodeBytes (i2osp x)
               <> CBOR.encodeInt (-3)
               <> CBOR.encodeBytes (i2osp y)
           _ -> error "never happens"
       )
encodePublicKey (EdDSAPublicKey key) =
  CBOR.encodeMapLen 4
    <> CBOR.encodeInt 1
    <> CBOR.encodeInt 1
    <> CBOR.encodeInt 3
    <> encodeCOSEAlgorithmIdentifier EdDSA
    <> CBOR.encodeInt (-1)
    <> case key of
      Ed25519 key ->
        CBOR.encodeInt 6
          <> CBOR.encodeInt (-2)
          <> CBOR.encodeBytes (ByteArray.convert key)
      Ed448 key ->
        CBOR.encodeInt 7
          <> CBOR.encodeInt (-2)
          <> CBOR.encodeBytes (ByteArray.convert key)

encodeCOSEAlgorithmIdentifier :: COSEAlgorithmIdentifier -> Encoding
encodeCOSEAlgorithmIdentifier x = CBOR.encodeInt $ case x of
  ECDSAIdentifier ES256 -> (-7)
  ECDSAIdentifier ES384 -> (-35)
  ECDSAIdentifier ES512 -> (-36)
  EdDSA -> (-8)

-- | Decodes a signature for a specific public key's type
-- Signatures are a bit weird in Webauthn.  For ES256 and RS256 they're ASN.1
-- and for EdDSA they're COSE
decodeECDSASignature :: ByteString -> Maybe ECDSA.Signature
decodeECDSASignature sigbs =
  case ASN1.decodeASN1' ASN1.BER sigbs of
    Left _ -> Nothing
    Right [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence] ->
      Just (ECDSA.Signature r s)
    Right _ -> Nothing

verify :: PublicKey -> ByteString -> ByteString -> Bool
verify key msg sig =
  case key of
    ECDSAPublicKey (ECDSAKey alg curve point) ->
      let key = ECDSA.PublicKey (toCurve curve) point
       in case decodeECDSASignature sig of
            Nothing -> False
            Just sig ->
              case alg of
                ES256 -> ECDSA.verify Hash.SHA256 key sig msg
                ES384 -> ECDSA.verify Hash.SHA384 key sig msg
                ES512 -> ECDSA.verify Hash.SHA512 key sig msg
    EdDSAPublicKey (Ed25519 key) ->
      case Ed25519.signature sig of
        CryptoPassed sig -> Ed25519.verify key msg sig
        CryptoFailed _ -> False
    EdDSAPublicKey (Ed448 key) ->
      case Ed448.signature sig of
        CryptoPassed sig -> Ed448.verify key msg sig
        CryptoFailed _ -> False
