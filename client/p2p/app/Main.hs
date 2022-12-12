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
import Data.Maybe (fromMaybe)
import System.CPUTime (getCPUTime)
import Text.Printf (printf)

maxPacketSize = 1024 * 7

fallbackPort = "9000"
kport = "9001"

size :: Int
size = 512
expt :: Integer
expt = 65537

type Plaintext = ByteString
type Ciphertext = ByteString
type AESEncryptionKey = ByteString

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
    Just iv -> pure $ fromMaybe "failed padding" (unpadPKCS7 $ cbcDecrypt aes iv dat)

keys :: MonadRandom m => m (ByteString, ByteString)
keys = do
  ekey <- genRandomBytes 32
  ivBytes <- genRandomBytes 16
  pure (ekey, ivBytes)

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

genAndSendAESKey :: Socket -> PublicKey -> IO AESKeyBytes
genAndSendAESKey socket recipientPubKey = do
                        (aesKey, _) <- keys
                        -- cyphertext <- aesEncrypt aesKey ivbuf "Hello"
                        emsg <- myencrypt recipientPubKey aesKey
                        sendAll socket emsg
                        pure aesKey

awaitForAes :: PrivateKey -> Socket -> Plaintext -> IO (Maybe ByteString)
awaitForAes priv soc confirmationmessage = do
  encryptedAesBytes <- recv soc maxPacketSize
  print "We got something boys"
  attemptedDecytpiton <- decryptSafer priv encryptedAesBytes
  case attemptedDecytpiton of
    Left e -> do
      print e
      pure Nothing
    Right aesBytes -> do
                   C.putStrLn aesBytes
                   putStrLn "Received and decrypted AES Key"
                   (_, ivbuf) <- keys
                   cyphertext <- aesEncrypt aesBytes ivbuf confirmationmessage
                   sendAll soc cyphertext
                   pure $ Just aesBytes

data ServerState = Echo
                 | ServerError String
                 | AwaitPublicKey ByteString
                 | AwaitSharedAES
                 | SendRandomNumber PublicKey AESKeyBytes
                 | AwaitRandomNumber AESKeyBytes ByteString
                 | AESEcho AESKeyBytes
                 -- abandoned
                 | AwaitAESEcryptedMessage AESKeyBytes
                 | Send2ndAESKey PublicKey
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
                                                      pure AwaitSharedAES
                                                    _ -> do
                                                      sendAll s r
                                                      pure Echo
                              AwaitSharedAES -> do
                                               maybeAES <- awaitForAes priv s "AES is working"
                                               case maybeAES of
                                                 Nothing -> pure $ ServerError "Failed to decrypt the aes key"
                                                 Just aesKey -> pure $ AwaitPublicKey aesKey

                              AwaitPublicKey aesKey -> do
                                               cpub <- recv s maxPacketSize
                                               print "We got the clients public key"
                                               C.putStrLn cpub
                                               fullPub <- aesDecrypt aesKey cpub
                                               let truPub = deserialize fullPub
                                               print "decryption ran"
                                               pure $ SendRandomNumber truPub aesKey
                              SendRandomNumber cpub aesKey -> do
                                               print "sending random number"
                                               cyphertext <- myencrypt cpub "hello"
                                               sendAll s cyphertext
                                               print "Random Number Sent"
                                               pure $ AwaitRandomNumber aesKey "hello"
                              AwaitRandomNumber aesKey ognum -> do
                                               em <- recv s maxPacketSize
                                               msg <- decryptSafer priv em
                                               case msg of
                                                 Left e -> pure $ ServerError (show e)
                                                 Right randnum -> do
                                                                  C.putStrLn $ "Received Random Number: " <> randnum
                                                                  if randnum == ognum then
                                                                      do putStrLn "numbers did match"
                                                                         pure $ AESEcho aesKey
                                                                  else do putStrLn "numbers did NOT match"
                                                                          pure $ ServerError "Random numbers did not match"
                              AESEcho aesKey -> do
                                               em <- recv s maxPacketSize
                                               msg <- aesDecrypt aesKey em
                                               (_, ivbuf) <- keys
                                               cyphertext <- aesEncrypt aesKey ivbuf msg
                                               sendAll s cyphertext
                                               pure $ AESEcho aesKey

                              -- Abandoned Path
                              AwaitAESEcryptedMessage aesKey -> do
                                               em <- recv s maxPacketSize
                                               msg <- aesDecrypt aesKey em
                                               C.putStrLn $ "Received: " <> msg
                                               pure $ ServerError "AwaitAESEcryptedMessage is abandonned"
                              Send2ndAESKey  cpub -> do
                                               print "Sending 2nd AES now"
                                               aesKey <- genAndSendAESKey s cpub
                                               pure $ ServerError "Send2ndAESKey is abandonned"



serverDispatcher :: Socket -> PrivateKey -> ServerState -> IO ServerState
serverDispatcher s priv state = do
  result <- mainServerDispatch s priv state
  case result of
    ServerError e -> pure $ ServerError e
    _ -> serverDispatcher s priv result

-- Server iterface which will use the public key of the client to
-- encrypt a message in this case "hello"
mainServer :: ServiceName -> PrivateKey -> IO ()
mainServer port priv =  do
  putStrLn ("Listening on " ++ port)
  runTCPServer Nothing port talk
      where
        talk s = do
          res <- serverDispatcher s priv Echo
          case res of
            Echo -> putStrLn "impossible"
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


-- --------------------------- Client Code ----------------------------------------
type AESKeyBytes = ByteString

data ClientState =
                 Fail String
                 -- | Recieve2ndAESKey AESKeyBytes -- abandoned path
                 | ConnectionRequest
                 | SendSharedAES
                 | SendAESHello AESKeyBytes
                 -- No encryption send
                 | SendHello

data ClientModel = ClientModel { clientKeys :: (PublicKey, PrivateKey)
                               , serverKey :: PublicKey
                               , soc :: Socket
                               , lastTime :: Integer
                               }

clientDispatcher :: ClientModel -> ClientState -> IO ClientState
clientDispatcher m state = do
  result <- clientDispatch m state
  case result of
    Fail e -> pure $ Fail e
    SendSharedAES -> do
        te <- getCPUTime
        let diff = fromIntegral (te  - lastTime m) / 1000000
        _ <- printf "Starting handshake took: %0.3f msec\n" (diff :: Double)
        ts <- getCPUTime
        clientDispatcher ClientModel{ clientKeys = clientKeys m
                                    , serverKey = serverKey m
                                    , soc = soc m
                                    , lastTime = ts}
                           result

    SendAESHello aeskey -> do
                te <- getCPUTime
                let diff = fromIntegral (te  - lastTime m) / (10^10)
                _ <- printf "Computation took: %0.3f msec\n" (diff :: Double)
                threadDelay 3000000
                ts <- getCPUTime
                clientDispatcher ClientModel{ clientKeys = clientKeys m
                                            , serverKey = serverKey m
                                            , soc = soc m
                                            , lastTime = ts}
                           result
    SendHello -> do
                te <- getCPUTime
                putStrLn $ "Ending timer at" ++ show te
                threadDelay 3000000
                ts <- getCPUTime
                putStrLn $ "Starting timer at" ++ show ts
                clientDispatcher m result
    _ -> clientDispatcher m result

--  No Encyr Public Key Iteration
--  Exposed Public Key Iteration
sendUnencryptedPublicKey :: ClientModel -> IO ClientState
sendUnencryptedPublicKey model = do
  print "sending message"
  sendAll (soc model) $ serialize $ serverKey model
  pure SendHello

sendPublicKeyEncryptedHello :: ClientModel -> IO ClientState
sendPublicKeyEncryptedHello model = do
  print "sending message"
  sendAll (soc model) $ serialize $ serverKey model
  pure SendHello
-- Initial Iteration
sendPlainHello :: ClientModel -> IO ClientState
sendPlainHello model = do
  sendAll (soc model)  "hello"
  em <- recv (soc model) maxPacketSize
  C.putStrLn $ "Received: " <> em
  pure SendHello

-- Public key iteration 1
sendPublicKeyHello :: ClientModel -> IO ClientState
sendPublicKeyHello model = do
  emsg <- myencrypt (serverKey model) "hello"
  sendAll (soc model) emsg
  pure SendHello

-- Public key iteration 2
-- sendMutualPublicKeyHello :: ClientModel -> IO ClientState
-- sendMutualPublicKeyHello model = do
--   print "sending message"
--   -- Send my public key
--   sendAll (soc model) (serialize (fst (clientKeys model)))
--   -- Send hello encrypted with server public key
--   emsg <- myencrypt (serverKey model) aesKey
--   sendAll socket emsg
--   sendAll (soc model) (serialize (fst (clientKeys model))
--   pure SendHello

-- Final iteration
sendUsingAES :: ClientModel -> IO ClientState
sendUsingAES model = do
  aesKey <- genAndSendAESKey (soc model) (serverKey model)
  _ <- receiveAESEcryptedMessage model aesKey
  sendPublicKeyWithAES model aesKey
  msg <- recieveRandomNumber model
  echoRandomNumber model msg
  pure $ SendAESHello aesKey

receiveAESEcryptedMessage :: ClientModel -> ByteString -> IO Plaintext
receiveAESEcryptedMessage model aesKey = do
  em <- recv (soc model) maxPacketSize
  msg <- aesDecrypt aesKey em
  C.putStrLn $ "Received: " <> msg
  pure msg

sendPublicKeyWithAES :: ClientModel -> ByteString -> IO ()
sendPublicKeyWithAES model aesKey = do
  print "sending message"
  (_, ivbuf) <- keys
  cyphertext <- aesEncrypt aesKey ivbuf (serialize (fst (clientKeys model)))
  sendAll (soc model) cyphertext

recieveRandomNumber :: ClientModel -> IO Plaintext
recieveRandomNumber model = do
  em <- recv (soc model) maxPacketSize
  attemptedDeycrpt <- decryptSafer (snd (clientKeys model)) em
  case attemptedDeycrpt of
    Left e -> undefined
    Right msg -> do
      C.putStrLn $ "Received Random Number: " <> msg
      pure $ msg

echoRandomNumber :: ClientModel -> Plaintext -> IO ()
echoRandomNumber model randnum = do
  cyphertext <- myencrypt (serverKey model) randnum
  sendAll (soc model) cyphertext
  pure ()

sendAESHello :: ClientModel -> ByteString -> IO ClientState
sendAESHello model aesKey = do
  (_, ivbuf) <- keys
  cyphertext <- aesEncrypt aesKey ivbuf "hello"
  sendAll (soc model) cyphertext
  em <- recv (soc model) maxPacketSize
  msg <- aesDecrypt aesKey em
  C.putStrLn $ "Received: " <> msg
  pure $ SendAESHello aesKey


sharedAESImplementaiont :: [ClientState]
sharedAESImplementaiont = [ConnectionRequest , SendSharedAES]

clientDispatch :: ClientModel -> ClientState -> IO ClientState
clientDispatch model cs = case cs of
                      Fail s -> do
                          print s
                          pure $ Fail s

                      ConnectionRequest -> do
                        e <- myencrypt (serverKey model) "Connect?"
                        sendAll (soc model) e
                        confirmation <- recv (soc model) maxPacketSize
                        case confirmation of
                          "YES" -> do
                            putStrLn "Connected at last"
                            sendUsingAES model
                          _ -> pure $ Fail "Failed To Get Confirmation"

                      SendSharedAES -> sendUsingAES model

                      SendAESHello aesKey -> sendAESHello model aesKey

                      SendHello -> sendPlainHello model


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
                                      t <- getCPUTime
                                      res <- clientDispatcher ClientModel{ clientKeys = (pub, priv)
                                                                         , serverKey = spub
                                                                         , soc = s
                                                                         , lastTime = t
                                                                         }
                                             ConnectionRequest
                                      case res of
                                        Fail e -> print e
                                        _ -> pure ()

main :: IO ()
main = getArgs >>= parse

serialize :: PublicKey -> ByteString
serialize pub = C.pack (show pub)

deserialize :: ByteString -> PublicKey
deserialize pub = read (C.unpack pub)

test = do
  (pub, _) <- RSA.generate size expt
  let s = serialize pub
      d = deserialize s
  unless (pub == d) (putStrLn "FAIL!! could not serialize proper")

--- CLI arguments ---

-- Server usage
parse :: [[Char]] -> IO ()
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

usage :: IO ()
usage   = putStrLn
          "Usage:command {endpoint} {ip-address} [-p port-number] \n\
\ command -h \n\
\   -h prints this help message \n\
\   -p sets the current port number (defaults to 9000)\n"

version :: IO ()
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
