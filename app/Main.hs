module Main where

import           Headers         (contextCreate, verify)
import           Implementations (SerializedSignature, breakSerializedSignature,
                                  deserializeRecoverable, hexToBytes,
                                  serializedSignature)

-- Test Inputs
    -- Serialized Signature  (65 bytes in hex) 'ee241b0e406661d43c1729a70ad0d7ef90cd13ad60c1065be0823196e23980270d0213d2af3f92478026381c567a2532b08ad06c0b349c7e9318ade44a9c2d0a00'
    -- Message Hash          (32 bytes in hex) '9902e8fe012a92c68276dfb7584a339587f8ffa859357e5a26a96af33ee25346'
    -- Private Key           (32 bytes in hex) 'c28a9f80738f770d527803a566cf6fc3edf6cea586c4fc4a5223a5ad797e1ac3'
    -- Public Key            (33 bytes in hex) '033d5c2875c9bd116875a71a5db64cffcb13396b163d039b1d9327824891804334'
    -- Public Key            (65 bytes in hex) '043d5c2875c9bd116875a71a5db64cffcb13396b163d039b1d932782489180433476a4352a2add00ebb0d5c94c515b72eb10f1fd8f3f03b42f4a2b255bfc9aa9e3'

-- #1
testCreateContext :: IO ()
testCreateContext = do
  x <- contextCreate verify
  print x

testBreakSerializedSignature :: IO ()
testBreakSerializedSignature = do
  case serializedSignature serSigBS of
    Nothing -> error "Could not parse ser sig"
    Just ss ->
      print $ show cs ++ " " ++ show rid
      where
        breaked = breakSerializedSignature ss
        cs = fst breaked
        rid = snd breaked
  where
      serSigBS = hexToBytes "ee241b0e406661d43c1729a70ad0d7ef90cd13ad60c1065be0823196e23980270d0213d2af3f92478026381c567a2532b08ad06c0b349c7e9318ade44a9c2d0a00"

testDeserializeRecoverable :: IO ()
testDeserializeRecoverable = do
  ctx <- contextCreate verify
  case serializedSignature serSigBS of
    Nothing -> error "Could not parse hex ser sig"
    Just serSig -> do
      case deserializeRecoverable ctx serSig of
        Nothing -> error "Could not deserialize ser sig"
        Just rs -> print rs
  where
    serSigBS = hexToBytes "ee241b0e406661d43c1729a70ad0d7ef90cd13ad60c1065be0823196e23980270d0213d2af3f92478026381c567a2532b08ad06c0b349c7e9318ade44a9c2d0a00"

main :: IO ()
main = testDeserializeRecoverable
