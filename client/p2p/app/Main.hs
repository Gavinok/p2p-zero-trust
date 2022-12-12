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
                 | SendRandomNumber AESKeyBytes
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
                                               pure $ SendRandomNumber aesKey
                              SendRandomNumber aesKey -> do
                                               print "sending random number"
                                               (_, ivbuf) <- keys
                                               cyphertext <- aesEncrypt aesKey ivbuf "hello"
                                               sendAll s cyphertext
                                               print "Random Number Sent"
                                               pure $ AwaitRandomNumber aesKey "hello"
                              AwaitRandomNumber aesKey ognum -> do
                                               em <- recv s maxPacketSize
                                               msg <- aesDecrypt aesKey em
                                               C.putStrLn $ "Received Random Number: " <> msg
                                               if msg == ognum then
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
                                               pure $ SendRandomNumber aesKey
                              Send2ndAESKey  cpub -> do
                                               print "Sending 2nd AES now"
                                               aesKey <- genAndSendAESKey s cpub
                                               pure $ AwaitAESEcryptedMessage aesKey



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


-- Client will send the server their public key recieve the enrypted
-- response
type AESKeyBytes = ByteString

data ClientState =
                 Fail String
                 | Recieve2ndAESKey AESKeyBytes -- abandoned path
                 | ConnectionRequest
                 | SendPublicKey AESKeyBytes
                 | SendSharedAES
                 | ReceiveAESEcryptedMessage AESKeyBytes
                 | RecieveRandomNumber AESKeyBytes
                 | EchoRandomNumber AESKeyBytes ByteString
                 | SendAESHello AESKeyBytes

clientDispatcher :: (PublicKey, PrivateKey) -> PublicKey -> Socket -> ClientState -> IO ClientState
clientDispatcher (cpub, cpriv) spub soc state = do
  result <- clientDispatch  (cpub, cpriv) spub soc state
  case result of
    Fail e -> pure $ Fail e
    _ -> clientDispatcher (cpub, cpriv) spub soc result

clientDispatch :: (PublicKey, PrivateKey) ->  PublicKey -> Socket -> ClientState -> IO ClientState
clientDispatch (cpub, cpriv) spub soc cs = case cs of
                      Fail s -> do
                          print s
                          pure $ Fail s

                      ConnectionRequest -> do
                        e <- myencrypt spub "Connect?"
                        sendAll soc e
                        confirmation <- recv soc maxPacketSize
                        case confirmation of
                          "YES" -> do
                            putStrLn "Connected at last"
                            pure SendSharedAES
                          _ -> pure $ Fail "FailedToGetConfirmation"

                      SendSharedAES -> do
                        aesKey <- genAndSendAESKey soc spub
                        pure $ ReceiveAESEcryptedMessage aesKey

                      ReceiveAESEcryptedMessage aesKey -> do
                        em <- recv soc maxPacketSize
                        msg <- aesDecrypt aesKey em
                        C.putStrLn $ "Received: " <> msg
                        pure $ SendPublicKey aesKey

                      SendPublicKey aesKey -> do
                        print "sending message"
                        (_, ivbuf) <- keys
                        cyphertext <- aesEncrypt aesKey ivbuf (serialize cpub)
                        sendAll soc cyphertext
                        pure $ RecieveRandomNumber aesKey

                      RecieveRandomNumber aesKey -> do
                                                     em <- recv soc maxPacketSize
                                                     msg <- aesDecrypt aesKey em
                                                     C.putStrLn $ "Received Random Numeber: " <> msg
                                                     pure $ EchoRandomNumber aesKey msg


                      EchoRandomNumber aesKey randnum -> do
                        (_, ivbuf) <- keys
                        cyphertext <- aesEncrypt aesKey ivbuf randnum
                        sendAll soc cyphertext
                        pure $ SendAESHello aesKey

                      SendAESHello aesKey -> do
                        (_, ivbuf) <- keys
                        cyphertext <- aesEncrypt aesKey ivbuf "hello"
                        sendAll soc cyphertext
                        em <- recv soc maxPacketSize
                        msg <- aesDecrypt aesKey em
                        C.putStrLn $ "Received: " <> msg
                        -- sleep 3 seconds
                        threadDelay 3000000
                        pure $ SendAESHello aesKey


                      -- XXX Abandoned Branch
                      Recieve2ndAESKey aesKey  -> do
                                                 maybeAesKey <- awaitForAes cpriv soc "2nd AES is working"
                                                 pure$ case maybeAesKey of
                                                   Nothing ->  Fail "Failed to decrypt the aes key"
                                                   Just aesKey2 -> Fail "Not implemented past recieving Recieve2ndAESKey"


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
                                      res <- clientDispatcher (pub, priv) spub s ConnectionRequest
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
