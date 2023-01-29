module Encryption (aesDecrypt
                  , aesEncrypt
                  , EncryptionMethod (..)
                  , Plaintext
                  , Ciphertext
                  , serialize
                  , deserialize
                  , AESKeyBytes
                  , mydecrypt
                  , myencrypt
                  , keys) where

-- AES Encryption
import Crypto.Cipher.AES as AES (AES256)
import Crypto.Cipher.Types (BlockCipher (..), Cipher (..), IV, cipherInit, makeIV)
import qualified Crypto.Data.Padding as PAD
import Crypto.Error (throwCryptoErrorIO)
import Crypto.PubKey.RSA as RSA
import Crypto.PubKey.RSA.PKCS15 as PKCS15
import Crypto.Random (MonadRandom)
import Crypto.Random.Types (getRandomBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as C
import Data.Maybe (fromMaybe)

data EncryptionMethod
  = NoEncryption
  | AES (Maybe AESKeyBytes)
  | OneWayRSA
  | TwoWayRSA

-- AES encryption support ---
type Plaintext = ByteString

type Ciphertext = ByteString

type AESKeyBytes = ByteString

genRandomBytes :: (MonadRandom m) => Int -> m ByteString
genRandomBytes size = do
  getRandomBytes size

initAES256 :: ByteString -> IO AES256
initAES256 = throwCryptoErrorIO . cipherInit

genIV :: ByteString -> Maybe (IV AES256)
genIV = makeIV

padPKCS7 :: Plaintext -> Plaintext
padPKCS7 = PAD.pad (PAD.PKCS7 16)

unpadPKCS7 :: Plaintext -> Maybe Plaintext
unpadPKCS7 = PAD.unpad (PAD.PKCS7 16)

aesEncrypt :: ByteString -> ByteString -> Plaintext -> IO Ciphertext
aesEncrypt ekey ivBytes msg = do
  aes <- initAES256 ekey
  pure $ case genIV ivBytes of
    Nothing -> "fail"
    Just iv -> ivBytes <> cbcEncrypt aes iv (padPKCS7 msg)

aesDecrypt :: ByteString -> Ciphertext -> IO Plaintext
aesDecrypt ekey ciphertext = do
  aes <- initAES256 ekey
  let (ivBytes, dat) = S.splitAt 16 ciphertext
  case genIV ivBytes of
    Nothing -> pure "fail"
    Just iv -> pure $ fromMaybe "failed padding" (unpadPKCS7 $ cbcDecrypt aes iv dat)

-- RSA encryption support ---
keys :: MonadRandom m => m (ByteString, ByteString)
keys = do
  ekey <- genRandomBytes 32
  ivBytes <- genRandomBytes 16
  pure (ekey, ivBytes)

mydecrypt :: MonadRandom m => PrivateKey -> ByteString -> m ByteString
mydecrypt pk msg = do
  d <- decryptSafer pk msg
  pure $ case d of
    Left _ -> "fail d" :: ByteString
    Right b -> b

myencrypt :: MonadRandom m => PublicKey -> ByteString -> m ByteString
myencrypt pk msg = do
  d <- PKCS15.encrypt pk msg
  pure $ case d of
    Left _ -> "fail e" :: ByteString
    Right b -> b

serialize :: PublicKey -> ByteString
serialize pub = C.pack (show pub)

deserialize :: ByteString -> PublicKey
deserialize pub = read (C.unpack pub)
