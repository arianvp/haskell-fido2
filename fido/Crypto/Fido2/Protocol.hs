{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.Fido2.Protocol
  ( AuthenticatorAttestationResponse (..),
    AuthenticatorAssertionResponse (..),
    AttestedCredentialData (..),
    PublicKeyCredentialCreationOptions (..),
    PublicKeyCredentialRequestOptions (..),
    PublicKeyCredentialRpEntity (..),
    PublicKeyCredentialParameters (..),
    PublicKeyCredentialUserEntity (..),
    PublicKeyCredentialDescriptor (..),
    AuthenticatorSelectionCriteria (..),
    AuthenticatorData (..),
    AttestationObject (..),
    ClientData (..),
    CredentialId (..),
    RpId (..),
    Origin (..),
    URLEncodedBase64 (..),
    PublicKeyCredential (..),
    WebauthnType (..),
    UserId (..),
    newUserId,
    Challenge,
    newChallenge,
    Timeout (..),
    PublicKeyCredentialType (..),
    ResidentKeyRequirement (..),
    UserVerificationRequirement (..),
    AuthenticatorAttachment (..),
    EncodingRules (..),
    verify,
  )
where

import Codec.CBOR.Decoding (Decoder)
import qualified Codec.CBOR.Read as CBOR
import Codec.CBOR.Term (Term (TBytes, TMap, TString))
import qualified Codec.Serialise.Class as Serialise
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Fido2.PublicKey (COSEAlgorithmIdentifier, PublicKey)
import qualified Crypto.Hash as Hash
import Crypto.Hash (Digest, SHA256)
import qualified Crypto.Random as Random
import Crypto.Random (MonadRandom)
import Data.Aeson (FromJSON, ToJSON)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Internal as Aeson
import qualified Data.Aeson.Parser as Aeson
import qualified Data.Aeson.Types as Aeson
import Data.Aeson.Types ((.:), (.:?))
import Data.Bifunctor (first)
import qualified Data.Binary.Get as Binary
import qualified Data.Bits as Bits
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Lazy as LBS
import qualified Data.HashMap.Strict as HashMap
import Data.HashMap.Strict (HashMap)
import Data.List.NonEmpty (NonEmpty)
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Data.Word (Word32, Word8)
import GHC.Generics (Generic, Rep)

newtype UserId = UserId URLEncodedBase64
  deriving newtype (Eq, Ord, FromJSON, ToJSON, Show)

-- | Webauthn highly suggets using 64 byte random strings for user-ids. Because
-- we do not want people to shoot themselves in the foot, we suggest you to use
-- this function to generate 'UserId's. However We also expose the constructor
-- of 'UserId' in case you already have existing 'UserId's that are secure
-- enough
newUserId :: MonadRandom m => m UserId
newUserId = UserId . URLEncodedBase64 <$> Random.getRandomBytes 64

-- | A valid domain string that identifies the WebAuthn Relying Party on whose
-- behalf a given registration or authentication ceremony is being performed. A
-- public key credential can only be used for authentication with the same
-- entity (as identified by RP ID) it was registered with.
--
-- By default, the RP ID for a WebAuthn operation is set to the caller’s
-- origin's effective domain. This default MAY be overridden by the caller, as
-- long as the caller-specified RP ID value is a registrable domain suffix of
-- or is equal to the caller’s origin's effective domain. See also §5.1.3
-- Create a New Credential - PublicKeyCredential’s [[Create]](origin, options,
-- sameOriginWithAncestors) Method and §5.1.4 Use an Existing Credential to
-- Make an Assertion - PublicKeyCredential’s [[Get]](options) Method.
newtype RpId = RpId {unRpId :: Text}
  deriving newtype (Eq, FromJSON, ToJSON, Show)

newtype Origin = Origin {unOrigin :: Text}
  deriving newtype (Eq, FromJSON, ToJSON, Show)

newtype Challenge = Challenge URLEncodedBase64
  deriving newtype (Eq, FromJSON, ToJSON, Show)

newChallenge :: MonadRandom m => m Challenge
newChallenge = Challenge . URLEncodedBase64 <$> Random.getRandomBytes 16

data PublicKeyCredential response
  = PublicKeyCredential
      { id :: Text,
        rawId :: CredentialId,
        response :: response,
        typ :: PublicKeyCredentialType
        -- clientExtensionResults ignored
      }
  deriving stock (Generic, Show)
  -- TODO use EncodingRules
  deriving (FromJSON) via (EncodingRules (PublicKeyCredential response))

newtype Timeout = Timeout Word32
  deriving stock (Generic, Show)
  deriving newtype (FromJSON, ToJSON)

-- | Information about the Relying Party responsible for a @PublicKeyCredentialCreationOptions@.
data PublicKeyCredentialRpEntity
  = PublicKeyCredentialRpEntity
      { -- | A unique identifier for the Relying Party entity, which sets the RP ID.
        id :: Maybe RpId,
        -- | A human-palatable identifier for the Relying Party, intended only for display.
        -- For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
        --
        -- Relying Parties SHOULD perform enforcement, as prescribed in Section
        -- 2.3 of [RFC8266] for the Nickname Profile of the PRECIS
        -- FreeformClass [RFC8264], when setting name's value, or displaying
        -- the value to the user.
        --
        -- Clients SHOULD perform enforcement, as prescribed in Section 2.3 of
        -- [RFC8266] for the Nickname Profile of the PRECIS FreeformClass
        -- [RFC8264], on name's value prior to displaying the value to the user
        -- or including the value as a parameter of the
        -- authenticatorMakeCredential operation.
        name :: Text
      }
  deriving stock (Generic, Show)
  deriving (ToJSON) via EncodingRules PublicKeyCredentialRpEntity

data PublicKeyCredentialUserEntity
  = PublicKeyCredentialUserEntity
      { -- | The user handle of the user account entity. A user handle is an
        -- opaque byte sequence with a maximum size of 64 bytes, and is not
        -- meant to be displayed to the user.  To ensure secure operation,
        -- authentication and authorization decisions MUST be made on the basis
        -- of this id member, not the 'displayName' nor 'name' members. See Section
        -- 6.1 of [RFC8266].  The user handle MUST NOT contain personally
        -- identifying information about the user, such as a username or e-mail
        -- address.
        id :: UserId,
        -- | A human-palatable name for the user account, intended only for
        -- display. For example, "Alex P. Müller" or "田中 倫". The Relying
        -- Party SHOULD let the user choose this, and SHOULD NOT restrict the
        -- choice more than necessary.
        displayName :: Text,
        -- | A human-palatable identifier for a user account. It is
        -- intended only for display, i.e., aiding the user in determining the
        -- difference between user accounts with similar displayNames. For
        -- example, "alexm", "alex.p.mueller@example.com" or "+14255551234".
        --
        -- The Relying Party MAY let the user choose this value. The Relying
        -- Party SHOULD perform enforcement, as prescribed in Section 3.4.3 of
        -- [RFC8265] for the UsernameCasePreserved Profile of the PRECIS
        -- IdentifierClass [RFC8264], when setting name's value, or displaying
        -- the value to the user.
        name :: Text
      }
  deriving stock (Generic, Show)
  deriving (ToJSON) via EncodingRules PublicKeyCredentialUserEntity

data PublicKeyCredentialParameters
  = PublicKeyCredentialParameters
      { typ :: PublicKeyCredentialType,
        alg :: COSEAlgorithmIdentifier
      }
  deriving stock (Generic, Show)
  deriving (ToJSON) via EncodingRules PublicKeyCredentialParameters

--  | Webauthn might introduce 'more types' in the future they say
data PublicKeyCredentialType = PublicKey
  deriving stock (Generic, Show)

instance ToJSON PublicKeyCredentialType where
  toJSON PublicKey = Aeson.String "public-key"

instance FromJSON PublicKeyCredentialType where
  parseJSON = Aeson.withText "type" $ \case
    "public-key" -> pure PublicKey
    x -> fail $ "unsupported type: " ++ (show x)

data AuthenticatorTransport
  = Usb
  | Nfc
  | Ble
  | Internal
  deriving (Show)

instance ToJSON AuthenticatorTransport where
  toJSON = Aeson.String . \case
    Usb -> "usb"
    Nfc -> "nfc"
    Ble -> "ble"
    Internal -> "internal"

data PublicKeyCredentialDescriptor
  = PublicKeyCredentialDescriptor
      { typ :: PublicKeyCredentialType,
        id :: CredentialId,
        transports :: Maybe [AuthenticatorTransport]
      }
  deriving stock (Generic, Show)
  deriving (ToJSON) via EncodingRules PublicKeyCredentialDescriptor

data AuthenticatorAttachment
  = Platform
  | CrossPlatform
  deriving stock (Show)

instance ToJSON AuthenticatorAttachment where
  toJSON = Aeson.String . \case
    Platform -> "platform"
    CrossPlatform -> "cross-platform"

data AttestationConveyancePreference
  = None
  | Indirect
  | Direct
  deriving stock (Show)

instance ToJSON AttestationConveyancePreference where
  toJSON = Aeson.String . \case
    None -> "none"
    Indirect -> "indirect"
    Direct -> "direct"

data ResidentKeyRequirement
  = ResidentKeyRequired
  | ResidentKeyPreferred
  | ResidentKeyDiscouraged
  deriving stock (Show)

instance ToJSON ResidentKeyRequirement where
  toJSON = Aeson.String . \case
    ResidentKeyRequired -> "required"
    ResidentKeyPreferred -> "preferred"
    ResidentKeyDiscouraged -> "discouraged"

data AuthenticatorSelectionCriteria
  = AuthenticatorSelectionCriteria
      { authenticatorAttachment :: Maybe AuthenticatorAttachment,
        -- , requireResidentKey :: Maybe Bool Deprecated it seems?
        residentKey :: Maybe ResidentKeyRequirement,
        -- Defaults to discouraged, but that leads to confusing behaviour in
        -- Chrome
        -- https://chromium.googlesource.com/chromium/src/+/master/content/browser/webauth/uv_preferred.md
        userVerification :: Maybe UserVerificationRequirement
      }
  deriving stock (Generic, Show)
  deriving (ToJSON) via EncodingRules AuthenticatorSelectionCriteria

data PublicKeyCredentialCreationOptions
  = PublicKeyCredentialCreationOptions
      { rp :: PublicKeyCredentialRpEntity,
        user :: PublicKeyCredentialUserEntity,
        challenge :: Challenge,
        pubKeyCredParams :: NonEmpty PublicKeyCredentialParameters,
        timeout :: Maybe Timeout,
        excludeCredentials :: Maybe [PublicKeyCredentialDescriptor],
        authenticatorSelection :: Maybe AuthenticatorSelectionCriteria,
        attestation :: Maybe AttestationConveyancePreference
        -- We do not support extensions yet
        -- , extensions  :: TODO
      }
  deriving stock (Generic, Show)
  deriving (ToJSON) via (EncodingRules PublicKeyCredentialCreationOptions)

data UserVerificationRequirement
  = UserVerificationRequired
  | UserVerificationPreferred
  | UserVerificationDiscouraged
  deriving stock (Generic, Show, Eq)

instance ToJSON UserVerificationRequirement where
  toJSON = Aeson.String . \case
    UserVerificationRequired -> "required"
    UserVerificationPreferred -> "preferred"
    UserVerificationDiscouraged -> "discouraged"

data PublicKeyCredentialRequestOptions
  = PublicKeyCredentialRequestOptions
      { challenge :: Challenge,
        timeout :: Maybe Timeout,
        rpId :: Maybe Text,
        -- TODO: Should be list of nonempty?
        allowCredentials :: Maybe [PublicKeyCredentialDescriptor],
        userVerification :: Maybe UserVerificationRequirement
      }
  deriving stock (Generic, Show)
  deriving (ToJSON) via (EncodingRules PublicKeyCredentialRequestOptions)

data AuthenticatorAssertionResponse
  = AuthenticatorAssertionResponse
      { clientData :: ClientData,
        authenticatorData :: AuthenticatorData,
        signature :: URLEncodedBase64,
        userHandle :: Maybe URLEncodedBase64
      }
  deriving stock (Show)

instance Aeson.FromJSON AuthenticatorAssertionResponse where
  parseJSON = Aeson.withObject "request" $ \obj -> do
    clientDataJSON' <- Text.encodeUtf8 <$> obj .: "clientDataJSON"
    authenticatorData' <- Text.encodeUtf8 <$> obj .: "authenticatorData"
    signature <- obj .: "signature"
    userHandle <- obj .:? "userHandle"
    either fail pure $ do
      clientDataJSON'' <- first ("ClientData" ++) $ Base64.decode clientDataJSON'
      clientData <- decodeClientData clientDataJSON''
      authenticatorData'' <- first ("AuthenticatorData" ++) $ Base64.decode authenticatorData'
      authenticatorData <- first show $ decodeAuthenticatorData' authenticatorData''
      pure $ AuthenticatorAssertionResponse clientData authenticatorData signature userHandle

data AuthenticatorAttestationResponse
  = AuthenticatorAttestationResponse
      { clientData :: ClientData,
        attestationObject :: AttestationObject
      }
  deriving (Show)

instance Aeson.FromJSON AuthenticatorAttestationResponse where
  parseJSON = Aeson.withObject "request" $ \obj -> do
    clientDataJSON' <- Text.encodeUtf8 <$> obj .: "clientDataJSON"
    attestationObject' <- Text.encodeUtf8 <$> obj .: "attestationObject"
    -- userId' <- Text.encodeUtf8 <$>  obj .: "userId"

    either fail pure $ do
      clientDataJSON'' <- first ("Clientdata" ++) $ Base64.decode clientDataJSON'
      clientData <- decodeClientData clientDataJSON''
      attestationObject'' <- first ("attestation" ++) $ Base64.decode attestationObject'
      attestationObject''' <- first show $ decodeAttestationObject attestationObject''
      pure $ AuthenticatorAttestationResponse clientData attestationObject'''

newtype URLEncodedBase64 = URLEncodedBase64 ByteString
  deriving newtype (Show, Eq, Ord)

instance Aeson.FromJSON URLEncodedBase64 where
  parseJSON = Aeson.withText "base64url" $ \t -> do
    either fail (pure . URLEncodedBase64) (Base64.decode $ Text.encodeUtf8 t)

instance Aeson.ToJSON URLEncodedBase64 where
  toJSON (URLEncodedBase64 bs) = Aeson.toJSON . Text.decodeUtf8 . Base64.encodeUnpadded $ bs

-- | We have our own type here because we want to avoid partial functions when
-- getting the X and Y values on the public curve. (Otherwise we'd have to deal
-- with the infinity point which should never occur in this program -- it's
-- not allowed by the COSE spec [1]).
--
-- You can use convertPointToCryptonite to get the representation that
-- cryptonite uses. In the future, this should allow us to decouple the
-- representation used for storage from the representation used to verify
-- signatures.
--
-- TODO(#22): Convert this to just the x value and the sign.
--
-- [1]: https://tools.ietf.org/html/draft-ietf-cose-msg-24#section-13.1.1
data Point = Point {x :: Integer, y :: Integer}
  deriving stock (Show)

data WebauthnType = Create | Get
  deriving (Eq, Show)

instance Aeson.FromJSON WebauthnType where
  parseJSON = Aeson.withText "WebauthnType" $ \case
    "webauthn.create" -> pure Create
    "webauthn.get" -> pure Get
    _ -> fail "Unknown type"

-- For attestation signatures, the authenticator MUST set the AT flag and
-- include the attestedCredentialData. For assertion signatures, the AT flag
-- MUST NOT be set and the attestedCredentialData MUST NOT be included.
--
-- AKA.   webauthn.create always implies AT
-- webauthn.get always implied ~AT
--
-- If the authenticator does not include any extension data, it MUST set the ED
-- flag to zero, and to one if extension data is included.
--
--

-- TODO: how about we make webauthnType a Type-level tag? Works nicely with servant
data ClientData
  = ClientData
      { typ :: WebauthnType,
        challenge :: Challenge, -- base64url-decoded
        origin :: Origin,
        clientDataHash :: Digest SHA256
        -- tokenBinding -- we don't implement so ignore
      }
  deriving (Show)

decodeClientData :: ByteString -> Either String ClientData
decodeClientData bs = do
  let hash = Hash.hash bs
  first snd (Aeson.eitherDecodeStrictWith Aeson.json (Aeson.iparse (clientDataParser hash)) bs)

clientDataParser :: Digest SHA256 -> Aeson.Value -> Aeson.Parser ClientData
clientDataParser hash = Aeson.withObject "ClientData" $ \o -> do
  typ <- o .: "type"
  challenge <- o .: "challenge"
  origin <- o .: "origin"
  pure $ ClientData typ challenge origin hash

newtype CredentialId = CredentialId URLEncodedBase64
  deriving newtype (Show, Eq, Ord, FromJSON, ToJSON)

data AttestedCredentialData
  = AttestedCredentialData
      { aaguid :: ByteString, -- 16 byte acceptable anchors guid, see step 15 of verifyAttestationResponse
        credentialId :: CredentialId, -- Length L
        credentialPublicKey :: PublicKey
      }
  deriving (Show)

data AttestedCredentialDataHeader
  = AttestedCredentialDataHeader
      { aaguid' :: ByteString, -- 16 byte
        credentialId' :: ByteString -- Length L
          -- , credentialPublicKey :: Value
      }
  deriving (Show)

-- The spec also gives this type an extensions field. We do
-- not implement this.
data AuthenticatorData
  = AuthenticatorData
      { rpIdHash :: Digest SHA256,
        -- , flags :: Word8
        counter :: Word32,
        userPresent :: Bool,
        userVerified :: Bool,
        attestedCredentialData :: Maybe AttestedCredentialData, -- Only present if bit 6 of flags is set, otherwise can be ignored
            -- TODO, better type?
            -- We don't support extensions. so we don't check the ED flag

        -- Used for verifying the signature currently. Not used for attestation in
        -- our current implementation which is why this is a maybe.
        rawData :: ByteString
      }
  deriving (Show)

data AuthenticatorDataRaw
  = AuthenticatorDataRaw
      { rpIdHash' :: Digest SHA256,
        flags' :: Word8,
        counter' :: Word32,
        attestedCredentialDataHeader' :: Maybe AttestedCredentialDataHeader
      }
  deriving (Show)

-- Attestation also contains an attestation statement. We really
-- want to see if we can avoid implementing this part of the
-- spec. We currently do not care about hardware verification, but
-- maybe this is also used for something else.
data AttestationObjectRaw
  = AttestationObjectRaw
      { authDataRaw :: ByteString,
        fmt :: Text,
        attStmt :: [(Term, Term)]
      }
  deriving (Show)

data AttestationFormat = FormatNone deriving (Show)

data AttestationObject
  = AttestationObject
      { authData :: AuthenticatorData,
        fmt :: Text,
        attStmt :: [(Term, Term)]
      }
  deriving (Show)

data Error = CBOR CBOR.DeserialiseFailure | Binary (LBS.ByteString, Binary.ByteOffset, String)
  deriving (Show)

decodeAttestationObject :: ByteString -> Either Error AttestationObject
decodeAttestationObject bs = do
  -- First decode the high level structure with decodeAttestationObjectRaw.
  -- Pass the remaining bytes to decodeAuthenticatorData
  -- TODO maybe use the incremental API here?
  (_rest, (AttestationObjectRaw {authDataRaw, fmt, attStmt})) <- first CBOR $ CBOR.deserialiseFromBytes decodeAttestationObjectRaw (LBS.fromStrict bs)
  (rest, _, authDataRaw') <- first Binary $ Binary.runGetOrFail decodeAuthenticatorDataRaw (LBS.fromStrict authDataRaw)
  (_rest, authData) <- first CBOR $ CBOR.deserialiseFromBytes (decodeAuthenticatorData authDataRaw authDataRaw') rest
  pure (AttestationObject authData fmt attStmt)

-- Helper. TODO  come up with more consistent names for all of these things, and allow
-- for some code re-use?
decodeAuthenticatorData' :: ByteString -> Either Error AuthenticatorData
decodeAuthenticatorData' bs = do
  (rest, _, authDataRaw) <- first Binary $ Binary.runGetOrFail decodeAuthenticatorDataRaw (LBS.fromStrict bs)
  (_rest, authData) <- first CBOR $ CBOR.deserialiseFromBytes (decodeAuthenticatorData bs authDataRaw) rest
  pure authData

-- The first parameter is a maybe bytestring in case we want to save the raw data
-- to the authenticatordata struct. This is ugly, but required because we need to
-- compute a hash based on the raw signature of this crap.
decodeAuthenticatorData :: ByteString -> AuthenticatorDataRaw -> Decoder s AuthenticatorData
decodeAuthenticatorData originalBs x = do
  let userPresent = Bits.testBit (flags' x) 0
  let userVerified = Bits.testBit (flags' x) 2
  attestedCredentialData <- traverse decodeAttestedCredentialData $ attestedCredentialDataHeader' x
  pure $
    AuthenticatorData
      { rpIdHash = rpIdHash' x,
        -- , flags = flags' x
        userPresent = userPresent,
        userVerified = userVerified,
        counter = counter' x,
        attestedCredentialData = attestedCredentialData,
        rawData = originalBs
      }

-- Effe voor de duidelijkheid. De bytes die overblijven van parsen van
-- attestedcredentialdataheader knallen we in deze
decodeAttestedCredentialData :: AttestedCredentialDataHeader -> Decoder s AttestedCredentialData
decodeAttestedCredentialData (AttestedCredentialDataHeader aaguid credentialId) = do
  AttestedCredentialData aaguid (CredentialId (URLEncodedBase64 credentialId)) <$> Serialise.decode

decodeAuthenticatorDataRaw :: Binary.Get AuthenticatorDataRaw
decodeAuthenticatorDataRaw = do
  rpIdHash <- maybe (fail "invalid digest") pure =<< (Hash.digestFromByteString <$> Binary.getByteString 32)
  flags <- Binary.getWord8
  counter <- Binary.getWord32be
  -- If bit 6 is set, attested credential data is included.
  header <-
    if Bits.testBit flags 6
      then Just <$> getAttestedCredentialDataHeader
      else pure Nothing
  -- If bit 7 is set, extension-defined authenticator data is included.
  _extensions <-
    if Bits.testBit flags 7
      then fail "Authenticator data extensions are currently not supported."
      else pure ()
  pure $ AuthenticatorDataRaw rpIdHash flags counter header

-- TODO: rename
getAttestedCredentialDataHeader :: Binary.Get AttestedCredentialDataHeader
getAttestedCredentialDataHeader = do
  aaguid <- Binary.getByteString 16
  len <- Binary.getWord16be
  credentialId <- Binary.getByteString (fromIntegral len)
  pure $ AttestedCredentialDataHeader aaguid credentialId

-- TODO: Decode proper map instead of a bunch of arbitrary assumptions!
decodeAttestationObjectRaw :: Decoder s AttestationObjectRaw
decodeAttestationObjectRaw = do
  map :: HashMap Text Term <- Serialise.decode
  TString fmt <- maybe (fail "no fmt") pure (HashMap.lookup "fmt" map)
  TMap attStmt <- maybe (fail "no attStmt") pure (HashMap.lookup "attStmt" map)
  -- TODO flags should tell whether authData is present, no?
  TBytes authDataRaw <- maybe (fail "no authData") pure (HashMap.lookup "authData" map)
  pure $ AttestationObjectRaw authDataRaw fmt attStmt

----- Encoding utils

newtype EncodingRules a = EncodingRules a

options :: Aeson.Options
options =
  Aeson.defaultOptions
    { Aeson.fieldLabelModifier = \x ->
        if x == "typ"
          then "type"
          else x,
      Aeson.omitNothingFields = True
    }

instance (Aeson.GToJSON Aeson.Zero (Rep a), Generic a) => ToJSON (EncodingRules a) where
  toJSON (EncodingRules a) = Aeson.genericToJSON options a

instance (Aeson.GFromJSON Aeson.Zero (Rep a), Generic a) => FromJSON (EncodingRules a) where
  parseJSON o = EncodingRules <$> Aeson.genericParseJSON options o

verify :: PublicKey -> AuthenticatorData -> ClientData -> ByteString -> Bool
verify pub AuthenticatorData {rawData} ClientData {clientDataHash} =
  PublicKey.verify pub (rawData <> convert clientDataHash)
