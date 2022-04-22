module Main where

import           SchnorrSecp256K1          (hexToBytes, ecrecover, getEthAddress)
import           SchnorrSecp256K1.Internal (contextCreate, verifyContext)

testEcrecover :: IO ()
testEcrecover = do
  ctx <- contextCreate verifyContext
  case ecrecover ctx (fromIntegral rawHash) (fromIntegral 27) (fromIntegral r) (fromIntegral s) of
    Nothing -> error "An error occurred while recovering eth address"
    Just ethAddr -> if (getEthAddress ethAddr) == ethAddrBS then print "ETH ADDRESSES MATCH!" else 
        error "An error occurred while recovering eth address"
  where
    r = 0xee241b0e406661d43c1729a70ad0d7ef90cd13ad60c1065be0823196e2398027
    s = 0x0d0213d2af3f92478026381c567a2532b08ad06c0b349c7e9318ade44a9c2d0a
    rawHash = 0x9902e8fe012a92c68276dfb7584a339587f8ffa859357e5a26a96af33ee25346
    ethAddrBS = hexToBytes "b9beb1d72e322de4b1f5f14abdbdaab50e310924"

main :: IO ()
main = testEcrecover
