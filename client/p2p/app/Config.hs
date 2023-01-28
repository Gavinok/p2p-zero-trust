module Config (maxPacketSize, currentHandshake, kport, size, expt, fallbackPort) where
import Encryption
import Network.Socket ( ServiceName)

maxPacketSize :: Int
maxPacketSize = 1024 * 7
-- The current iteration being testd
currentHandshake :: EncryptionMethod
currentHandshake = TwoWayRSA

kport :: ServiceName
kport = "9001"
size :: Int
size = 512
expt :: Integer
expt = 65537

fallbackPort :: ServiceName
fallbackPort = "9000"
