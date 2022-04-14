module Main where

import           Headers         (contextCreate, verify)
import           Implementations (hexToBytes, messageHash, serializedSignature,
                                  uncompressedPublicKey, verifySignature)

testVerify :: IO ()
testVerify = do
  ctx <- contextCreate verify
  case serializedSignature serSigBS of
    Nothing -> error "An error occurred while reading signature"
    Just serSig -> case messageHash msgHashBS of
      Nothing -> error "An error occurred while reading message hash"
      Just msgHash -> case uncompressedPublicKey pubKeyBS of
        Nothing -> error "An error occurred while reading public key"
        Just pubKey -> case verifySignature ctx serSig msgHash pubKey of
          Nothing -> error "An error occurred while verifying signature"
          Just verified ->
            if verified
              then print "Signature is valid"
            else
              print "Signature not valid"
  where
    serSigBS = hexToBytes "ee241b0e406661d43c1729a70ad0d7ef90cd13ad60c1065be0823196e23980270d0213d2af3f92478026381c567a2532b08ad06c0b349c7e9318ade44a9c2d0a00"
    msgHashBS = hexToBytes "9902e8fe012a92c68276dfb7584a339587f8ffa859357e5a26a96af33ee25346"
    pubKeyBS = hexToBytes "043d5c2875c9bd116875a71a5db64cffcb13396b163d039b1d932782489180433476a4352a2add00ebb0d5c94c515b72eb10f1fd8f3f03b42f4a2b255bfc9aa9e3"

main :: IO ()
main = testVerify
