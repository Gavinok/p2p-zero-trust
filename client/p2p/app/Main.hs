module Main where

-- Echo server program
import Control.Concurrent (forkFinally, threadDelay, forkIO, ThreadId)
import qualified Control.Exception as E
import Control.Monad (unless, forever, void)
import qualified Data.ByteString as S
import Network.Socket
import qualified Data.ByteString.Char8 as C
import Network.Socket.ByteString (recv, sendAll)

-- https://hackage.haskell.org/package/cryptonite-0.30/docs/Crypto-Tutorial.html
import Crypto.PubKey.RSA as RSA
import Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.Data.Padding as PAD

-- AES Encryption
import Crypto.Cipher.AES as AES
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (BlockCipher(..), Cipher(..), nullIV, KeySizeSpecifier(..), IV, makeIV, cipherInit, )
import Crypto.Random.Types (getRandomBytes)
import Crypto.Error (CryptoFailable(..), CryptoError(..), throwCryptoErrorIO)

import System.Environment
import System.Exit
import Crypto.Random (MonadRandom)
import Data.ByteString (ByteString)
import Data.ByteArray (ByteArray, convert)

maxPacketSize = 1024 * 7

fallbackPort = "9000"
kport = "9001"

size :: Int
size = 512
expt :: Integer
expt = 65537

type Plaintext = ByteString
type Ciphertext = ByteString


-- randomSymmetricKeys :: IO m => BotClient -> m SymmetricKeys
-- randomSymmetricKeys clt =
--   SymmetricKeys
--     <$> randomBytes (botClientBox clt) 32
--     <*> randomBytes (botClientBox clt) 32

-- data SymmetricKeys = SymmetricKeys
--   { symmetricEncKey :: !ByteString,
--     symmetricMacKey :: !ByteString
--   }
--   deriving (Eq, Show)

type AESEncryptionKey = ByteString
-- -- | Not required, but most general implementation
-- data Key c a where
--   Key :: (BlockCipher c, ByteArray a) => a -> Key c a

-- -- | Generates a string of bytes (key) of a specific length for a given block cipher
-- genSecretKey :: forall m c a. (MonadRandom m, ByteArray a) => Int -> m AESEncryptionKey
-- genSecretKey _ = getRandomBytes _


-- randomBytes :: IO m => Box -> Word32 -> m ByteString
-- randomBytes b n = liftIO $ CBox.randomBytes b n >>= unwrap >>= CBox.copyBytes

genRandomBytes :: forall m c a. (MonadRandom m) => Int -> m ByteString
genRandomBytes size = do
  getRandomBytes size

-- tmp :: forall m c a. (MonadRandom m, BlockCipher c) => c -> (Maybe (IV AES256))

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
    Just iv -> do
        pure $ case unpadPKCS7 $ cbcDecrypt aes iv dat of
               Nothing -> "failed padding"
               Just unpadded -> unpadded

keys :: MonadRandom m => m (ByteString, ByteString)
keys = do
  ekey <- genRandomBytes 32
  ivBytes <- genRandomBytes 16
  pure (ekey, ivBytes)

fullTest = do
  (ekey, ivb) <- keys
  cipher <- aesEncrypt ekey ivb "Testing encryption"
  aesDecrypt ekey cipher

mydecrypt :: MonadRandom m => PrivateKey -> ByteString -> m ByteString
mydecrypt pk msg = do d <- decryptSafer pk msg
                      pure $ case d of
                               Left _ ->  "fail d" :: ByteString
                               Right b -> b

myencrypt :: MonadRandom m => PublicKey -> ByteString -> m ByteString
myencrypt pk msg = do d <- PKCS15.encrypt pk msg
                      pure $ case d of
                               Left _ ->  "fail e" :: ByteString
                               Right b -> b

pubToString :: PublicKey -> ByteString
pubToString pub = C.pack (show pub)

stringToPk :: ByteString -> PublicKey
stringToPk pub = read $ C.unpack pub

pq :: MonadRandom m => ByteString -> m ByteString
pq msg = do x <- RSA.generate size expt
            tmp <- PKCS15.encrypt (fst x) msg
            d <- decryptSafer (snd x) $ case tmp of
                                          Left _ ->  "fail e" :: ByteString
                                          Right b -> b
            pure $ case d of
                     Left _ -> "fail d" :: ByteString
                     Right y -> y


data ServerState = Echo
                 | AwaitPublicKey ByteString Socket
                 | ServerError String
                 | AwaitSharedAES Socket
                 | Send2ndAESKey PublicKey Socket
-- mainServerDispatch :: Socket -> PrivateKey -> ServerState -> IO ServerState
mainServerDispatch :: Socket -> PrivateKey -> ServerState -> IO ServerState
mainServerDispatch s priv state = case state of
                              ServerError e -> do print e
                                                  pure $ ServerError e
                              Echo -> do
                                     msg <- recv s maxPacketSize
                                     decr <- decryptSafer priv msg
                                     case decr of
                                       Left _ -> pure $ ServerError "Failed to decrypt"
                                       Right r -> case C.unpack r of
                                                    "Connect?" -> do
                                                      sendAll s "YES"
                                                      print "now connected"
                                                      mainServerDispatch s priv $ AwaitSharedAES s
                                                    _ -> do
                                                      sendAll s r
                                                      mainServerDispatch s priv Echo
                              AwaitSharedAES soc -> do
                                               encryptedAesBytes <- recv soc maxPacketSize
                                               print "We got something boys"
                                               attemptedDecytpiton <- decryptSafer priv encryptedAesBytes
                                               case attemptedDecytpiton of
                                                 Left e -> do
                                                     print e
                                                     pure $ ServerError "Failed to decrypt the aes key"
                                                 Right aesBytes -> do
                                                      C.putStrLn aesBytes
                                                      (_, ivbuf) <- keys
                                                      cyphertext <- aesEncrypt aesBytes ivbuf "AES is working"
                                                      sendAll s cyphertext
                                                      mainServerDispatch s priv $ AwaitPublicKey aesBytes soc

                              AwaitPublicKey aesKey soc -> do
                                               cpub <- recv soc maxPacketSize
                                               print "We got the clients public key"
                                               C.putStrLn cpub
                                               fullPub <- aesDecrypt aesKey cpub
                                               let truPub = deserialize fullPub
                                               print "decryption ran"
                                               mainServerDispatch s priv $ Send2ndAESKey truPub soc
                              Send2ndAESKey  cpub soc -> do
                                               (aesKey, ivbuf) <- keys
                                               emsg <- myencrypt cpub aesKey
                                               print "Sending 2nd AES now"
                                               sendAll s emsg
                                               em <- recv s maxPacketSize
                                               msg <- aesDecrypt aesKey em
                                               C.putStrLn $ "Received: " <> msg
                                               pure $ ServerError "not implemented past sending AES key"


-- Server iterface which will use the public key of the client to
-- encrypt a message in this case "hello"
mainServer :: ServiceName -> PrivateKey -> IO ()
mainServer port priv =  do
  putStrLn ("Listening on " ++ port)
  runTCPServer Nothing port talk
      where
        talk s = do
          res <- mainServerDispatch s priv Echo
          case res of
            Echo -> putStrLn "imposibles"
            ServerError e -> print e


keyServer :: ServiceName -> PublicKey -> IO ()
keyServer port pub = do
    putStrLn ("Key served on " ++ port)
    runTCPServer Nothing port talk
      where
        talk s = do
                _ <- recv s maxPacketSize
                sendAll s $ serialize pub
                talk s

server :: ServiceName -> ServiceName -> IO ()
server keyPort connectionPort = do
   (public, private) <- RSA.generate size expt
   _ <- forkIO $ keyServer keyPort public
   mainServer connectionPort private


-- Client will send the server their public key recieve the enrypted
-- response
type AESKeyBytes = ByteString

data Error = FailedToGetConfirmation String
data ClientState =
                 ConnectionRequest PublicKey Socket
                 | SendPublicKey ByteString PublicKey Socket
                 | SendSharedAES PublicKey Socket
                 | ReviveAESEcryptedMessage Socket AESKeyBytes
                 | Recieve2ndAESKey AESKeyBytes Socket
                 | Fail String



clientDispatch :: (PublicKey, PrivateKey) ->  PublicKey -> ClientState -> IO ClientState
clientDispatch (cpub, cpriv) spub cs = case cs of
                      Fail s -> do
                          print s
                          pure $ Fail s

                      ConnectionRequest pub s -> do
                        e <- myencrypt spub "Connect?"
                        sendAll s e
                        confirmation <- recv s maxPacketSize
                        case confirmation of
                          "YES" -> do
                            putStrLn "Connected at last"
                            clientDispatch (cpub, cpriv) spub $ SendSharedAES spub s
                          _ -> pure $ Fail "FailedToGetConfirmation"

                      SendSharedAES pub s -> do
                        (aesKey, ivbuf) <- keys
                        -- cyphertext <- aesEncrypt aesKey ivbuf "Hello"
                        emsg <- myencrypt spub aesKey
                        sendAll s emsg
                        clientDispatch (cpub, cpriv) spub $ ReviveAESEcryptedMessage s aesKey
                      ReviveAESEcryptedMessage s aesKey -> do
                        em <- recv s maxPacketSize
                        msg <- aesDecrypt aesKey em
                        C.putStrLn $ "Received: " <> msg
                        -- sleep 3 seconds
                        threadDelay 3000000
                        clientDispatch (cpub, cpriv) spub $ SendPublicKey aesKey cpub s
                      SendPublicKey aesKey pub s -> do
                        print "sending message"
                        (_, ivbuf) <- keys
                        cyphertext <- aesEncrypt aesKey ivbuf (serialize cpub)
                        sendAll s cyphertext
                        -- encrypted using my public key
                        -- em <- recv s maxPacketSize
                        -- d <- mydecrypt cpriv em
                        -- C.putStrLn $ "Received: " <> d
                        clientDispatch (cpub, cpriv) spub $ Recieve2ndAESKey aesKey s
                      Recieve2ndAESKey aesKey soc -> do
                        encryptedAesBytes <- recv soc maxPacketSize
                        print "We got something boys"
                        attemptedDecytpiton <- decryptSafer cpriv encryptedAesBytes
                        case attemptedDecytpiton of
                          Left e -> do
                            print e
                            pure $ Fail "Failed to decrypt the aes key"
                          Right aesBytes -> do
                            (_, ivbuf) <- keys
                            putStrLn "Sending 2nd aes confirmation"
                            cyphertext <- aesEncrypt aesBytes ivbuf "2nd AES is working"
                            sendAll soc cyphertext
                            pure $ Fail "Not implemented past recieving Recieve2ndAESKey"
                        -- encripted <- PKCS15.encrypt spub (serialize cpub)
                        -- case encripted of
                        --   Left e -> do
                        --       print e
                        --       pure $ Fail "Failed to encrypt with RSA"
                        --   Right emsg -> do
                        --              print "senidng my pub key"
                        --              sendAll s emsg
                        --              resp <- recv s maxPacketSize
                        --              decr <- decryptSafer cpriv resp
                        --              case decr of
                        --                Left _ -> pure $ Fail "Failed to decrypt with RSA"
                        --                Right r -> do
                        --                          C.putStrLn $ ("Received" :: ByteString) <> r
                        --             -- pure  $ ServerError "Failed to decrypt"
                        --                          clientDispatch (cpub, cpriv) spub $ SendSharedAES pub s


client :: HostName -> ServiceName -> IO ()
client host port = do
    runTCPClient host kport $ \s -> do
                     sendAll s "find"
                     spubBytes <- recv s maxPacketSize
                     let spub = deserialize spubBytes
                     print spub
                     runTCPClient host port $ \s -> do
                                      (pub, priv) <- RSA.generate size expt
                                      -- putStr $ show pub
                                      res <- clientDispatch (pub, priv) spub $ ConnectionRequest pub s
                                      case res of
                                        Fail e -> print e
                                        _ -> pure ()
                                      -- putStr "YYYYYYY: "
                                      -- sendAll s $ serialize pub
                                      -- msg <- recv s maxPacketSize
                                      -- putStr "Received: "
                                      -- d <- mydecrypt priv msg
                                      -- C.putStrLn d
                                      -- threadDelay 3000000

main :: IO ()
main = getArgs >>= parse

serialize :: PublicKey -> ByteString
serialize pub = C.pack (show pub)

deserialize :: ByteString -> PublicKey
deserialize pub = read (C.unpack pub)

test = do
  (pub, priv) <- RSA.generate size expt
  let s = serialize pub
      d = deserialize s
  unless (pub == d) (putStrLn "FAIL!! could not serialize proper")

--- CLI arguments ---

-- Server usage
parse ["server", _ , "-p", port] = server kport port >> exitSuccess
parse ["server", _] = server kport fallbackPort >> exitSuccess

-- Client Usage
parse ["client", host, "-p", port] = client host port >> exitSuccess
parse ["client", "localhost"] = client "127.0.0.1" fallbackPort >> exitSuccess
parse ["client", host] = client host fallbackPort >> exitSuccess

-- Special cases
parse ["-h"] = usage   >> exitSuccess
parse ["-v"] = version >> exitSuccess
parse _ = usage >> exitFailure

usage   = putStrLn
          "Usage:command {endpoint} {ip-address} [-p port-number] \n\
\ command -h \n\
\   -h prints this help message \n\
\   -p sets the current port number (defaults to 9000)\n"

version = putStrLn "p2p version 0.1"



--- The ugly part of the backends


-- from the "network-run" package.
runTCPServer :: Maybe HostName -> ServiceName -> (Socket -> IO a) -> IO a
runTCPServer mhost port server = withSocketsDo $ do
    addr <- resolve
    E.bracket (open addr) close loop
  where
    resolve = do
        let hints = defaultHints {
                addrFlags = [AI_PASSIVE]
              , addrSocketType = Stream
              }
        head <$> getAddrInfo (Just hints) mhost (Just port)
    open addr = E.bracketOnError (openSocket addr) close $ \sock -> do
        setSocketOption sock ReuseAddr 1
        withFdSocket sock setCloseOnExecIfNeeded
        bind sock $ addrAddress addr
        listen sock 1024
        return sock
    loop sock = forever $ E.bracketOnError (accept sock) (close . fst)
        $ \(conn, _peer) -> void $
            -- 'forkFinally' alone is unlikely to fail thus leaking @conn@,
            -- but 'E.bracketOnError' above will be necessary if some
            -- non-atomic setups (e.g. spawning a subprocess to handle
            -- @conn@) before proper cleanup of @conn@ is your case
            forkFinally (server conn) (const $ gracefulClose conn 5000)

-- from the "network-run" package.
runTCPClient :: HostName -> ServiceName -> (Socket -> IO a) -> IO a
runTCPClient host port client = withSocketsDo $ do
    addr <- resolve
    E.bracket (open addr) close client
  where
    resolve = do
        let hints = defaultHints { addrSocketType = Stream }
        head <$> getAddrInfo (Just hints) (Just host) (Just port)
    open addr = E.bracketOnError (openSocket addr) close $ \sock -> do
        connect sock $ addrAddress addr
        return sock
