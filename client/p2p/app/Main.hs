module Main where

-- Echo server program
import Control.Concurrent (forkFinally, threadDelay, forkIO)
import qualified Control.Exception as E
import Control.Monad (forever, void)
import qualified Data.ByteString as S
import Network.Socket
    ( setCloseOnExecIfNeeded,
      defaultHints,
      getAddrInfo,
      openSocket,
      withSocketsDo,
      setSocketOption,
      gracefulClose,
      accept,
      bind,
      connect,
      listen,
      close,
      withFdSocket,
      AddrInfo(addrAddress, addrFlags, addrSocketType),
      AddrInfoFlag(AI_PASSIVE),
      HostName,
      ServiceName,
      SocketOption(ReuseAddr),
      Socket,
      SocketType(Stream) )
import qualified Data.ByteString.Char8 as C
import Network.Socket.ByteString (recv, sendAll)

-- https://hackage.haskell.org/package/cryptonite-0.30/docs/Crypto-Tutorial.html
import Crypto.PubKey.RSA as RSA
import Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.Data.Padding as PAD

-- AES Encryption
import Crypto.Cipher.AES as AES ( AES256 )
import Crypto.Cipher.Types (BlockCipher(..), Cipher(..), IV, makeIV, cipherInit, )
import Crypto.Random.Types (getRandomBytes)
import Crypto.Error (throwCryptoErrorIO)

import System.Environment ( getArgs )
import System.Exit ( exitFailure, exitSuccess )
import Crypto.Random (MonadRandom)
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import System.CPUTime (getCPUTime)
import Text.Printf (printf)

maxPacketSize :: Int
maxPacketSize = 1024 * 7

fallbackPort :: ServiceName
fallbackPort = "9000"

kport :: ServiceName
kport = "9001"

size :: Int
size = 512
expt :: Integer
expt = 65537

--- Modularity Of Different Iterations ---

-- The current iteration being testd
currentHandshake :: EncryptionMethod
currentHandshake = TwoWayRSA

--- Server Path being followed
serverHandshake :: ServerModel -> EncryptionMethod -> IO ServerState
serverHandshake model NoEncryption  = do
  msg <- recv (s model) maxPacketSize
  sendAll (s model) msg
  pure Echo
serverHandshake model OneWayRSA = echoOneWayEncrypt model
serverHandshake model TwoWayRSA = echoTwoWayEncrypt model
serverHandshake model (AES _)  = awaitSharedAES model

--- Client path being followed
clientHandshake :: ClientModel -> EncryptionMethod -> IO ClientState
clientHandshake model NoEncryption  = sendHello model NoEncryption
clientHandshake model OneWayRSA = sendHello model OneWayRSA
clientHandshake model TwoWayRSA = do
  sendAll (soc model) $ serialize (fst (clientKeys model))
  sendHello model TwoWayRSA
clientHandshake model (AES _)  = sendUsingAES model


-- RSA encryption support ---
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

serialize :: PublicKey -> ByteString
serialize pub = C.pack (show pub)

deserialize :: ByteString -> PublicKey
deserialize pub = read (C.unpack pub)

-- AES encryption support ---
type Plaintext = ByteString
type Ciphertext = ByteString
type AESEncryptionKey = ByteString

genRandomBytes :: forall m c a. (MonadRandom m) => Int -> m ByteString
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

genAndSendAESKey :: Socket -> PublicKey -> IO AESKeyBytes
genAndSendAESKey socket recipientPubKey = do
                        (aesKey, _) <- keys
                        emsg <- myencrypt recipientPubKey aesKey
                        sendAll socket emsg
                        pure aesKey

awaitForAes :: PrivateKey -> Socket -> Plaintext -> IO (Maybe ByteString)
awaitForAes priv soc confirmationmessage = do
  encryptedAesBytes <- recv soc maxPacketSize
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
                 | WaitForConnection
                 | ServerError String

data ServerModel = ServerModel { priv :: PrivateKey
                               , s :: Socket
                               }

data EncryptionMethod = NoEncryption
                      | AES (Maybe AESKeyBytes)
                      | OneWayRSA
                      | TwoWayRSA

-- Final
awaitSharedAES :: ServerModel -> IO ServerState
awaitSharedAES model = do
                 maybeAES <- awaitForAes (priv model) (s model) "AES is working"
                 case maybeAES of
                   Nothing -> pure $ ServerError "Failed to decrypt the aes key"
                   Just aesKey -> awaitPublicKey model aesKey

awaitPublicKey :: ServerModel -> ByteString -> IO ServerState
awaitPublicKey model aesKey = do
                 cpub <- recv (s model) maxPacketSize
                 C.putStrLn cpub
                 fullPub <- aesDecrypt aesKey cpub
                 let truPub = deserialize fullPub
                 sendRandomNumber model truPub aesKey

sendRandomNumber :: ServerModel -> PublicKey -> ByteString -> IO ServerState
sendRandomNumber model cpub aesKey = do
                 cyphertext <- myencrypt cpub "hello"
                 sendAll (s model) cyphertext
                 awaitRandomNumber model aesKey "hello"

awaitRandomNumber :: ServerModel -> ByteString -> ByteString -> IO ServerState
awaitRandomNumber model aesKey ognum = do
                 em <- recv (s model) maxPacketSize
                 msg <- decryptSafer (priv model) em
                 case msg of
                   Left e -> pure $ ServerError (show e)
                   Right randnum -> do
                                    C.putStrLn $ "Received Random Number: " <> randnum
                                    if randnum == ognum then
                                        do putStrLn "numbers did match"
                                           aESEcho model aesKey
                                    else do putStrLn "numbers did NOT match"
                                            pure $ ServerError "Random numbers did not match"

aESEcho :: ServerModel -> ByteString -> IO ServerState
aESEcho model aesKey = do
                 em <- recv (s model) maxPacketSize
                 msg <- aesDecrypt aesKey em
                 (_, ivbuf) <- keys
                 cyphertext <- aesEncrypt aesKey ivbuf msg
                 sendAll (s model) cyphertext
                 aESEcho model aesKey
-- Initial
-- Nothing needed since Echo works out of the box
-- One Way RSA
echoOneWayEncrypt :: ServerModel -> IO ServerState
echoOneWayEncrypt model = do
                 ehello <- recv (s model) maxPacketSize
                 dhello <- decryptSafer (priv model) ehello
                 case dhello of
                   Left e -> pure $ ServerError (show e)
                   Right hello -> do
                               sendAll (s model) hello
                               echoOneWayEncrypt model
-- Two Way RSA
echoTwoWayEncrypt :: ServerModel -> IO ServerState
echoTwoWayEncrypt model = do
                 -- Wait for the client to provide thier public key
                 scpub <- recv (s model) maxPacketSize
                 let cpub = deserialize scpub
                 echoWithCpub cpub
                 where echoWithCpub cpub = do
                            ehello <- recv (s model) maxPacketSize
                            dhello <- decryptSafer (priv model) ehello
                            case dhello of
                              Left e -> pure $ ServerError (show e)
                              Right hello -> do
                                          newehello <- myencrypt cpub hello
                                          sendAll (s model) newehello
                                          echoWithCpub cpub


--- Server code sed for dispatching against the current Finite State
mainServerDispatch :: ServerModel -> ServerState -> IO ServerState
mainServerDispatch m state = case state of
                              ServerError e -> do print e
                                                  pure $ ServerError e
                              WaitForConnection -> do
                                     msg <- recv (s m) maxPacketSize
                                     decr <- decryptSafer (priv m) msg
                                     case decr of
                                       Left _ -> pure $ ServerError "Failed to decrypt"
                                       Right r -> case C.unpack r of
                                                    "Connect?" -> do
                                                      sendAll (s m) "YES"
                                                      serverHandshake m currentHandshake
                                                    _ -> pure $ ServerError "Failed to connect"
                              Echo -> do
                                msg <- recv (s m) maxPacketSize
                                sendAll (s m) msg
                                pure Echo

serverDispatcher :: ServerModel -> ServerState -> IO ServerState
serverDispatcher m state = do
  result <- mainServerDispatch m state
  case result of
    ServerError e -> pure $ ServerError e
    _ -> serverDispatcher m result

-- Main thread server interfaced with by the client other than the initial public key request
mainServer :: ServiceName -> PrivateKey -> IO ()
mainServer port priv =  do
  putStrLn ("Listening on " ++ port)
  runTCPServer Nothing port talk
      where
        talk s = do
          res <- serverDispatcher ServerModel{ s = s
                                             , priv = priv}
                 WaitForConnection
          case res of
            Echo -> putStrLn "impossible"
            ServerError e -> print e

--- Server hosting the current public key
keyServer :: ServiceName -> PublicKey -> IO ()
keyServer port pub = do
    putStrLn ("Key served on " ++ port)
    runTCPServer Nothing port talk
      where
        talk talksocket = do
                _ <- recv talksocket maxPacketSize
                sendAll talksocket $ serialize pub
                talk talksocket

server :: ServiceName -> ServiceName -> IO ()
server keyPort connectionPort = do
   (public, private) <- RSA.generate size expt
   _ <- forkIO $ keyServer keyPort public
   mainServer connectionPort private


-- --------------------------- Client Code ----------------------------------------
type AESKeyBytes = ByteString


data ClientState =
                 Fail String
                 | ConnectionRequest
                 | HandShakeStart EncryptionMethod
                 -- No encryption send
                 | SendHello EncryptionMethod

data ClientModel = ClientModel { clientKeys :: (PublicKey, PrivateKey)
                               , serverKey :: PublicKey
                               , soc :: Socket
                               , lastTime :: Integer
                               }

-- Used to monitor the state of the client and keep a tally of the current time 
clientDispatcher :: ClientModel -> ClientState -> IO ClientState
clientDispatcher m state = do
  result <- clientDispatch m state
  case result of
    HandShakeStart _ -> do
        te <- getCPUTime
        let diff = fromIntegral (te  - lastTime m) / 1000000
        _ <- printf "Handshake started in: %0.3f msec\n" (diff :: Double)
        ts <- getCPUTime
        clientDispatcher ClientModel{ clientKeys = clientKeys m
                                    , serverKey = serverKey m
                                    , soc = soc m
                                    , lastTime = ts}
              result

    SendHello _ -> waitAndRunAgain result
    Fail e -> pure $ Fail e
    _ -> clientDispatcher m result
    where waitAndRunAgain result = do
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

clientDispatch :: ClientModel -> ClientState -> IO ClientState
clientDispatch model cs = case cs of
                      Fail errorMsg -> do
                          print errorMsg
                          pure $ Fail errorMsg
                      HandShakeStart m -> clientHandshake model m
                      ConnectionRequest -> do
                        e <- myencrypt (serverKey model) "Connect?"
                        sendAll (soc model) e
                        confirmation <- recv (soc model) maxPacketSize
                        case confirmation of
                          "YES" -> do
                            putStrLn "Connected at last"
                            pure $ HandShakeStart currentHandshake
                          _ -> pure $ Fail "Failed To Get Confirmation"

                      SendHello meth -> sendHello model meth


client :: HostName -> ServiceName -> IO ()
client host port = do
    runTCPClient host kport $ \s -> do
                     sendAll s "find"
                     spubBytes <- recv s maxPacketSize
                     let spub = deserialize spubBytes
                     print spub
                     runTCPClient host port $ \s -> do
                                      (pub, priv) <- RSA.generate size expt
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
-- Final iteration
receiveAESEcryptedMessage :: ClientModel -> ByteString -> IO Plaintext
receiveAESEcryptedMessage model aesKey = do
  em <- recv (soc model) maxPacketSize
  msg <- aesDecrypt aesKey em
  C.putStrLn $ "Received: " <> msg
  pure msg

sendPublicKeyWithAES :: ClientModel -> ByteString -> IO ()
sendPublicKeyWithAES model aesKey = do
  (_, ivbuf) <- keys
  cyphertext <- aesEncrypt aesKey ivbuf (serialize (fst (clientKeys model)))
  sendAll (soc model) cyphertext

recieveRandomNumber :: ClientModel -> IO Plaintext
recieveRandomNumber model = do
  em <- recv (soc model) maxPacketSize
  attemptedDeycrpt <- decryptSafer (snd (clientKeys model)) em
  case attemptedDeycrpt of
    Left _ -> undefined
    Right msg -> do
      pure msg

echoRandomNumber :: ClientModel -> Plaintext -> IO ()
echoRandomNumber model randnum = do
  cyphertext <- myencrypt (serverKey model) randnum
  sendAll (soc model) cyphertext
  pure ()

sendUsingAES :: ClientModel -> IO ClientState
sendUsingAES model = do
  aesKey <- genAndSendAESKey (soc model) (serverKey model)
  _ <- receiveAESEcryptedMessage model aesKey
  sendPublicKeyWithAES model aesKey
  msg <- recieveRandomNumber model
  echoRandomNumber model msg
  sendHello model $ AES (Just aesKey)

sendHello :: ClientModel -> EncryptionMethod -> IO ClientState
sendHello model (AES (Just aesKey)) = do
  (_, ivbuf) <- keys
  cyphertext <- aesEncrypt aesKey ivbuf "hello"
  sendAll (soc model) cyphertext
  em <- recv (soc model) maxPacketSize
  msg <- aesDecrypt aesKey em
  C.putStrLn $ "Received: " <> msg
  pure $ SendHello (AES (Just aesKey))

-- Shared AES Iteration
sendHello _ (AES Nothing) = do
  putStrLn "Must have AES to echo"
  pure $ Fail "Must have AES to echo"

-- No Encryption Iteration
sendHello model NoEncryption = do
  sendAll (soc model)  "hello"
  em <- recv (soc model) maxPacketSize
  C.putStrLn $ "Received: " <> em
  pure $ SendHello NoEncryption

-- One Way Public Key Iteration
sendHello model OneWayRSA = do
  emsg <- myencrypt (serverKey model) "hello"
  sendAll (soc model) emsg
  em <- recv (soc model) maxPacketSize
  C.putStrLn $ "Received: " <> em
  pure $ SendHello OneWayRSA

-- Two Way Public Key Iteration
sendHello model TwoWayRSA = do
 -- Send my public key
  emsg <- myencrypt (serverKey model) "hello"
  sendAll (soc model) emsg
  em <- recv (soc model) maxPacketSize
  attemptedDecryption <- decryptSafer (snd (clientKeys model)) em
  case attemptedDecryption of
    Left e -> pure $ Fail (show e)
    Right m -> do
      C.putStrLn $ "Received: " <> m
      pure $ SendHello TwoWayRSA

--- CLI arguments ---
main :: IO ()
main = getArgs >>= parse

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

--- Backends used for the client and server ---

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
