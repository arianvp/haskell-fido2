{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module PublicKeySpec
  ( spec,
  )
where

import qualified Codec.CBOR.Encoding as CBOR
import qualified Codec.CBOR.FlatTerm as FlatTerm
import qualified Codec.CBOR.JSON as JSON
import qualified Codec.CBOR.Read as Read
import qualified Codec.CBOR.Write as Write
import qualified Codec.Serialise as Serialise
import qualified Codec.Serialise.Properties as Serialise.Properties
import Crypto.Fido2.PublicKey
import Crypto.Hash (SHA384 (SHA384))
import Crypto.Hash.Algorithms (SHA256 (SHA256))
import Crypto.Hash.Algorithms (SHA512 (SHA512))
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.Random as Random
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Prim as ASN1
import qualified Data.Aeson as Aeson
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Test.Hspec
import Test.QuickCheck (counterexample, (===), (==>), Arbitrary, Gen, arbitrary, elements, frequency, oneof, property)
import Test.QuickCheck.Instances.ByteString

instance Arbitrary ECDSAIdentifier where
  arbitrary = elements [ES256, ES384, ES512]

instance Arbitrary COSEAlgorithmIdentifier where
  arbitrary = frequency [(1, pure EdDSA), (3, ECDSAIdentifier <$> arbitrary)]

instance Arbitrary EdDSAKey where
  arbitrary = Ed25519 . Ed25519.toPublic <$> randomEd25519Key

instance Arbitrary ECDSAKey where
  arbitrary =
    oneof
      [ uncurry (ECDSAKey ES256) . getPoint <$> arbitrary,
        uncurry (ECDSAKey ES384) . getPoint <$> arbitrary,
        uncurry (ECDSAKey ES512) . getPoint <$> arbitrary
      ]

instance Arbitrary CurveIdentifier where
  arbitrary = elements [P256, P384, P521]

instance Arbitrary PublicKey where
  arbitrary = oneof [EdDSAPublicKey <$> arbitrary, ECDSAPublicKey <$> arbitrary]

instance Arbitrary Ed25519.SecretKey where
  arbitrary = randomEd25519Key

randomEd25519Key :: Gen Ed25519.SecretKey
randomEd25519Key = do
  rng <- Random.drgNewSeed . Random.seedFromInteger <$> arbitrary
  let (a, _) = Random.withDRG rng Ed25519.generateSecretKey
  pure a

newtype ECDSAKeyPair = ECDSAKeyPair (CurveIdentifier, (ECDSA.PublicKey, ECDSA.PrivateKey)) deriving (Eq, Show)

privateKey :: ECDSAKeyPair -> ECDSA.PrivateKey
privateKey (ECDSAKeyPair (_, (_, priv))) = priv

getPublicKey :: ECDSAIdentifier -> ECDSAKeyPair -> PublicKey
getPublicKey alg (ECDSAKeyPair (crv, (pub, priv))) = ECDSAPublicKey $ ECDSAKey alg crv (ECDSA.public_q pub)

getPoint :: ECDSAKeyPair -> (CurveIdentifier, ECC.Point)
getPoint (ECDSAKeyPair (ident, (pub, priv))) = (ident, ECDSA.public_q pub)

instance Arbitrary ECDSAKeyPair where
  arbitrary = ECDSAKeyPair <$> randomECDSAKey

randomECDSAKey :: Gen (CurveIdentifier, (ECDSA.PublicKey, ECDSA.PrivateKey))
randomECDSAKey = do
  curveIdentifier <- arbitrary
  let curve = toCurve curveIdentifier
  rng <- Random.drgNewSeed . Random.seedFromInteger <$> arbitrary
  let (x, _) = Random.withDRG rng (ECC.generate curve)
  pure (curveIdentifier, x)

spec :: SpecWith ()
spec = do
  let roundtrips :: forall a. (Eq a, Show a, Serialise.Serialise a, Arbitrary a) => SpecWith ()
      roundtrips = do
        it "serialiseIdentity" $ property $ \(key :: a) ->
          Serialise.Properties.serialiseIdentity key
        it "flatTermIdentity" $ property $ \(key :: a) ->
          Serialise.Properties.flatTermIdentity key
        it "hasValidFlatTerm" $ property $ \(key :: a) ->
          Serialise.Properties.hasValidFlatTerm key
  describe "PublicKey" $ do
    roundtrips @PublicKey
    describe "EdDSA" $ do
      it "accepts valid signatures"
        $ property
        $ \(secret :: Ed25519.SecretKey, bytes :: ByteString) ->
          let pub = Ed25519.toPublic secret
              sig = Ed25519.sign secret pub bytes
           in verify (EdDSAPublicKey (Ed25519 pub)) bytes (convert sig)
    describe "ECDSA" $ do
      it "accepts valid signatures"
        $ property
        $ \(keyPair :: ECDSAKeyPair, bytes :: ByteString, alg :: ECDSAIdentifier, seed :: Integer) ->
          let drg = Random.drgNewSeed . Random.seedFromInteger $ seed
              (ECDSA.Signature r s, _) = case alg of
                ES256 -> Random.withDRG drg $ ECDSA.sign (privateKey keyPair) SHA256 bytes
                ES384 -> Random.withDRG drg $ ECDSA.sign (privateKey keyPair) SHA384 bytes
                ES512 -> Random.withDRG drg $ ECDSA.sign (privateKey keyPair) SHA512 bytes
           in verify (getPublicKey alg keyPair) bytes (ASN1.encodeASN1' ASN1.DER [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence])
      it "rejects invalid signatures"
        $ property
        $ \(keyPair :: ECDSAKeyPair, bytes :: ByteString, alg :: ECDSAIdentifier, r, s) ->
          not
            $ verify (getPublicKey alg keyPair) bytes
            $ ASN1.encodeASN1' ASN1.DER [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence]
      it "rejects invalid ASN.1"
        $ property
        $ \(keyPair :: ECDSAKeyPair, bytes :: ByteString, alg :: ECDSAIdentifier, r, s) ->
          not
            $ verify (getPublicKey alg keyPair) bytes
            $ ASN1.encodeASN1' ASN1.DER [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s]
      it "`alg` implies `crv`" $ property $ \(key :: ECDSAKey) ->
        -- TODO: Make the test fail during signature; not during deserializaiton
        -- then later make the illegal state irrepresentable
        (alg key == ES256 && crv key /= P256)
          ==> let x = FlatTerm.toFlatTerm . Serialise.encode . ECDSAPublicKey $ key
               in counterexample (show x) $ case FlatTerm.fromFlatTerm @PublicKey Serialise.decode x of
                    Left _ -> True
                    Right _ -> False
  describe "COSEAlgorithmIdentifier" $ do
    roundtrips @COSEAlgorithmIdentifier
    it "fails to decode unspported COSEAlgorithmIdentifiers" $ do
      let bs = Write.toLazyByteString (CBOR.encodeInt (-300))
      Serialise.deserialiseOrFail @COSEAlgorithmIdentifier bs `shouldSatisfy` \x ->
        case x of
          Left (Read.DeserialiseFailure _ "Unsupported `alg`") -> True
          _ -> False
    it "can encode COSEAlgorithmIdentifier as JSON" $ do
      property $ \(alg :: COSEAlgorithmIdentifier) ->
        let bs = Serialise.serialise alg
            rs = Read.deserialiseFromBytes (JSON.decodeValue False) bs
         in pure (Aeson.toJSON alg) == (snd <$> rs)
