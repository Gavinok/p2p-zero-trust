module Main (main) where

-- Echo server program
import Control.Concurrent (forkFinally, forkIO)
import qualified Control.Exception as E
import Control.Monad (forever, void)
import Client
import Config
import Encryption
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

-- AES Encryption

import System.Environment ( getArgs )
import System.Exit ( exitFailure, exitSuccess )
import Data.ByteString (ByteString)

--- Server Path being followed
serverHandshake :: ServerModel -> EncryptionMethod -> IO ServerState
serverHandshake model NoEncryption  = do
  msg <- recv (s model) maxPacketSize
  sendAll (s model) msg
  pure Echo
serverHandshake model OneWayRSA = echoOneWayEncrypt model
serverHandshake model TwoWayRSA = echoTwoWayEncrypt model
serverHandshake model (AES _)  = awaitSharedAES model

data ServerState = Echo
                 | WaitForConnection
                 | ServerError String

data ServerModel =
    ServerModel { priv :: PrivateKey
                , s :: Socket
                }

-- Final
awaitSharedAES :: ServerModel -> IO ServerState
awaitSharedAES model = do
                 maybeAES <- awaitForAes (priv model) (s model) "AES is working"
                 case maybeAES of
                   Nothing -> pure
                               $ ServerError "Failed to decrypt the aes key"
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
                 myencrypt cpub "hello" >>= sendAll (s model)
                 awaitRandomNumber model aesKey "hello"

awaitRandomNumber :: ServerModel -> ByteString -> ByteString -> IO ServerState
awaitRandomNumber (ServerModel priv_ s_) aesKey ognum = do
                 msg <- recv s_ maxPacketSize >>= decryptSafer priv_
                 case msg of
                   Left e -> pure $ ServerError (show e)
                   Right randnum -> do
                            C.putStrLn $ "Received Random Number: " <> randnum
                            if randnum == ognum then
                                do putStrLn "numbers did match"
                                   aESEcho (ServerModel priv_ s_) aesKey
                            else
                                do putStrLn "numbers did NOT match"
                                   pure
                                    $ ServerError "Random numbers did not match"

aESEcho :: ServerModel -> ByteString -> IO ServerState
aESEcho model aesKey = do
                 msg <- recv (s model) maxPacketSize >>= aesDecrypt aesKey
                 (_, ivbuf) <- keys
                 cyphertext <- aesEncrypt aesKey ivbuf msg
                 sendAll (s model) cyphertext
                 aESEcho model aesKey
-- Initial
-- Nothing needed since Echo works out of the box
-- One Way RSA
echoOneWayEncrypt :: ServerModel -> IO ServerState
echoOneWayEncrypt (ServerModel priv_ s_) = do
                 dhello <- recv s_ maxPacketSize >>= decryptSafer priv_
                 case dhello of
                   Left e -> pure $ ServerError (show e)
                   Right hello -> do
                               sendAll s_ hello
                               echoOneWayEncrypt
                                  $ ServerModel priv_ s_
-- Two Way RSA
echoTwoWayEncrypt :: ServerModel -> IO ServerState
echoTwoWayEncrypt (ServerModel priv_ s_) = do
                 -- Wait for the client to provide thier public key
                 scpub <- recv s_ maxPacketSize
                 let cpub = deserialize scpub
                 echoWithCpub cpub
                 where echoWithCpub cpub = do
                            dhello <- recv s_ maxPacketSize >>= decryptSafer priv_
                            case dhello of
                              Left e -> pure $ ServerError (show e)
                              Right hello -> do
                                          myencrypt cpub hello >>= sendAll s_
                                          echoWithCpub cpub


--- Server code sed for dispatching against the current Finite State
mainServerDispatch :: ServerModel -> ServerState -> IO ServerState
mainServerDispatch m state =
    case state of
      ServerError e -> do print e
                          pure $ ServerError e
      WaitForConnection -> do
                 msg <- recv (s m) maxPacketSize >>= decryptSafer (priv m)
                 case msg of
                   Left _ -> pure $ ServerError "Failed to decrypt"
                   Right r -> case C.unpack r of
                                "Connect?" -> do
                                  sendAll (s m) "YES"
                                  serverHandshake m currentHandshake
                                _ -> pure
                                     $ ServerError "Failed to connect"
      Echo -> do
        recv (s m) maxPacketSize >>= sendAll (s m)
        pure Echo

serverDispatcher :: ServerModel -> ServerState -> IO ServerState
serverDispatcher m state = do
  result <- mainServerDispatch m state
  case result of
    ServerError e -> pure $ ServerError e
    _ -> serverDispatcher m result

-- Main thread server interfaced with by the client other than the
-- initial public key request
mainServer :: ServiceName -> PrivateKey -> IO ()
mainServer port priv_ =  do
  putStrLn ("Listening on " ++ port)
  runTCPServer Nothing port talk
      where
        talk s_ = do
          res <- serverDispatcher ServerModel{ s = s_
                                             , priv = priv_}
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

