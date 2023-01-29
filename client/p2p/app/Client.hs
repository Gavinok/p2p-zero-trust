module Client (client, awaitForAes) where
import Encryption
import Config
import Control.Concurrent (threadDelay)
import qualified Data.ByteString.Char8 as C
import System.CPUTime (getCPUTime)
import Crypto.PubKey.RSA as RSA
import Crypto.PubKey.RSA.PKCS15 as PKCS15
import Text.Printf (printf)
import qualified Control.Exception as E
import Network.Socket.ByteString (recv, sendAll)
import Network.Socket
    ( defaultHints,
      getAddrInfo,
      openSocket,
      withSocketsDo,
      connect,
      close,
      AddrInfo(addrAddress, addrSocketType),
      HostName,
      ServiceName,
      Socket,
      SocketType(Stream) )

-- --------------------------- Client Code ----------------------------------------
genAndSendAESKey :: Socket -> PublicKey -> IO AESKeyBytes
genAndSendAESKey socket recipientPubKey = do
                        (aesKey, _) <- keys
                        emsg <- myencrypt recipientPubKey aesKey
                        sendAll socket emsg
                        pure aesKey

awaitForAes :: PrivateKey -> Socket -> Plaintext -> IO (Maybe C.ByteString)
awaitForAes priv soc_ confirmationmessage = do
  attemptedDecytpiton <- recv soc_ maxPacketSize >>= decryptSafer priv
  case attemptedDecytpiton of
    Left e -> print e >> pure Nothing
    Right aesBytes -> do
                   C.putStrLn aesBytes
                   putStrLn "Received and decrypted AES Key"
                   (_, ivbuf) <- keys
                   aesEncrypt
                      aesBytes ivbuf
                      confirmationmessage >>= sendAll soc_
                   pure $ Just aesBytes

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
                let diff = fromIntegral (te  - lastTime m) / ((10^10) :: Double)
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
                        myencrypt (serverKey model) "Connect?" >>= sendAll (soc model)
                        confirmation <- recv (soc model) maxPacketSize
                        case confirmation of
                          "YES" -> do
                            putStrLn "Connected at last"
                            pure $ HandShakeStart currentHandshake
                          _ -> pure $ Fail "Failed To Get Confirmation"

                      SendHello meth -> sendHello model meth


client :: HostName -> ServiceName -> IO ()
client host port =
    runTCPClient host kport $ \s -> do
                     sendAll s "find"
                     spubBytes <- recv s maxPacketSize
                     let spub = deserialize spubBytes
                     print spub
                     runTCPClient host port $ \s_ -> do
                                      (pub, priv) <- RSA.generate size expt
                                      t <- getCPUTime
                                      res <- clientDispatcher
                                                    ClientModel{ clientKeys = (pub, priv)
                                                               , serverKey = spub
                                                               , soc = s_
                                                               , lastTime = t
                                                               }
                                             ConnectionRequest
                                      case res of
                                        Fail e -> print e
                                        _ -> pure ()
-- Final iteration
receiveAESEcryptedMessage :: ClientModel -> C.ByteString -> IO Plaintext
receiveAESEcryptedMessage (ClientModel  _ _ soc_ _ ) aesKey = do
  msg <- recv soc_ maxPacketSize >>= aesDecrypt aesKey
  C.putStrLn $ "Received: " <> msg
  pure msg

sendPublicKeyWithAES :: ClientModel -> C.ByteString -> IO ()
sendPublicKeyWithAES (ClientModel  (cpub_ , _) _ soc_ _ ) aesKey = do
  (_, ivbuf) <- keys
  cyphertext <- aesEncrypt aesKey ivbuf $ serialize cpub_
  sendAll soc_ cyphertext

recieveRandomNumber :: ClientModel -> IO Plaintext
recieveRandomNumber (ClientModel  (_ , cpriv_) _ soc_ _ ) = do
  attemptedDeycrpt <- recv soc_ maxPacketSize >>= decryptSafer cpriv_
  case attemptedDeycrpt of
    Left _ -> undefined
    Right msg -> do
      pure msg

echoRandomNumber :: ClientModel -> Plaintext -> IO ()
echoRandomNumber (ClientModel _ serverKey_ soc_ _ ) randnum = do
  cyphertext <- myencrypt serverKey_ randnum
  sendAll soc_ cyphertext
  pure ()

sendUsingAES :: ClientModel -> IO ClientState
sendUsingAES model = do
  aesKey <- genAndSendAESKey (soc model) (serverKey model)
  _ <- receiveAESEcryptedMessage model aesKey
  sendPublicKeyWithAES model aesKey
  recieveRandomNumber model >>= echoRandomNumber model
  sendHello model $ AES (Just aesKey)

sendHello :: ClientModel -> EncryptionMethod -> IO ClientState
sendHello (ClientModel _ _ soc_ _ ) (AES (Just aesKey)) = do
  (_, ivbuf) <- keys
  cyphertext <- aesEncrypt aesKey ivbuf "hello"
  sendAll soc_ cyphertext
  msg <- recv soc_ maxPacketSize >>= aesDecrypt aesKey
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
  myencrypt (serverKey model) "hello" >>= sendAll (soc model)
  recv (soc model) maxPacketSize >>= C.putStrLn . mappend "Received: "
  pure $ SendHello OneWayRSA

-- Two Way Public Key Iteration
sendHello  (ClientModel (_, cpriv) spub_ soc_ _) TwoWayRSA = do
 -- Send my public key
  myencrypt spub_ "hello" >>= sendAll soc_
  attemptedDecryption <- recv soc_ maxPacketSize >>= decryptSafer cpriv
  case attemptedDecryption of
    Left e -> pure $ Fail (show e)
    Right m -> do
      C.putStrLn $ "Received: " <> m
      pure $ SendHello TwoWayRSA

--- Client path being followed
clientHandshake :: ClientModel -> EncryptionMethod -> IO ClientState
clientHandshake model NoEncryption  = sendHello model NoEncryption
clientHandshake model OneWayRSA = sendHello model OneWayRSA
clientHandshake model TwoWayRSA = do
  sendAll (soc model) $ serialize (fst (clientKeys model))
  sendHello model TwoWayRSA
clientHandshake model (AES _)  = sendUsingAES model

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
