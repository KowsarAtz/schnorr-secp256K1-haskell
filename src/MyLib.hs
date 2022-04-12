module MyLib (createContext, verify) where

import Foreign
  ( -- FunPtr,
    Ptr,
    -- castPtr
  )
import Foreign.C
  ( -- CInt (..),
    -- CSize (..),
    -- CString,
    -- CUChar,
    CUInt (..),
  )

data LCtx -- FIXME: change name

type Context = Ptr LCtx

type ContextType = CUInt

verify :: ContextType
verify = 0x0101

foreign import ccall safe "secp256k1.h secp256k1_context_create"
  createContext ::
    ContextType ->
    IO Context