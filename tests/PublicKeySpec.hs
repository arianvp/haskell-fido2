{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module PublicKeySpec (spec) where

import qualified Codec.CBOR.Encoding as CBOR
import qualified Codec.CBOR.Write as Write
import qualified Codec.Serialise as Serialise
import Crypto.Fido2.PublicKey
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.Random as Random
import Test.Hspec
import Test.QuickCheck ((===), Arbitrary, Gen, arbitrary, elements, oneof, property)
import Data.Either (isLeft)

instance Arbitrary ECDSAIdentifier where
  arbitrary = elements [ES256, ES384, ES512]

instance Arbitrary COSEAlgorithmIdentifier where
  arbitrary = oneof [pure EdDSA, arbitrary]

instance Arbitrary EdDSAKey where
  arbitrary =
    oneof
      [ Ed25519 <$> randomEd25519PublicKey,
        Ed448 <$> randomEd448PublicKey
      ]

instance Arbitrary ECDSAKey where
  arbitrary =
    oneof
      [ uncurry (ECDSAKey ES256) <$> randomECDSAPublicKey,
        uncurry (ECDSAKey ES384) <$> randomECDSAPublicKey,
        uncurry (ECDSAKey ES512) <$> randomECDSAPublicKey
      ]

instance Arbitrary CurveIdentifier where
  arbitrary = elements [P256, P384, P521]

instance Arbitrary PublicKey where
  arbitrary = oneof [EdDSAPublicKey <$> arbitrary, ECDSAPublicKey <$> arbitrary]

randomEd25519PublicKey :: Gen Ed25519.PublicKey
randomEd25519PublicKey = do
  rng <- Random.drgNewSeed . Random.seedFromInteger <$> arbitrary
  let (a, _) = Random.withDRG rng (Ed25519.toPublic <$> Ed25519.generateSecretKey)
  pure a

randomEd448PublicKey :: Gen Ed448.PublicKey
randomEd448PublicKey = do
  rng <- Random.drgNewSeed . Random.seedFromInteger <$> arbitrary
  let (a, _) = Random.withDRG rng (Ed448.toPublic <$> Ed448.generateSecretKey)
  pure a

randomECDSAPublicKey :: Gen (CurveIdentifier, ECC.Point)
randomECDSAPublicKey = do
  curveIdentifier <- arbitrary
  let curve = toCurve curveIdentifier
  rng <- Random.drgNewSeed . Random.seedFromInteger <$> arbitrary
  let ((ECDSA.PublicKey _ point, _), _) = Random.withDRG rng (ECC.generate curve)
  pure (curveIdentifier, point)

spec :: SpecWith ()
spec = do
  it "roundtrips" $ do
    property $ \(key :: PublicKey) -> do
      let bs = Serialise.serialise key
      let rs = Serialise.deserialiseOrFail bs
      rs === pure key
  it "fails to decode unspported COSEAlgorithmIdentifiers" $  do
    let bs = Write.toLazyByteString (CBOR.encodeInt (-300))
    Serialise.deserialiseOrFail @COSEAlgorithmIdentifier bs `shouldSatisfy` isLeft