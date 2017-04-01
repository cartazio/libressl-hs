
module Network.Libre.TLS where


import Control.Monad.Primitive
import Network.Libre.TLS.FFI.Internal
import Foreign.C.Types
import Foreign.Ptr
import Foreign.C.String
import System.Posix.Types

primWriteCallback :: (PrimBase m)
  =>  (TLSPtr -> {-Ptr a-}  CString -> CSize -> Ptr b -> m CSsize)
      -> m  (FunPtr (TlsWriteCallback b))
primWriteCallback = \ f -> ( unsafePrimToPrim $
  mkWriteCB $! (\tl buf buflen arg -> unsafePrimToIO $  f tl buf buflen arg ))

primReadCallback :: (PrimBase m)
  =>  (TLSPtr -> {-Ptr a-}  CString -> CSize -> Ptr b -> m CSsize)
      -> m  (FunPtr (TlsReadCallback b))
primReadCallback = \ f -> ( unsafePrimToPrim $
  mkReadCB $! (\tl buf buflen arg -> unsafePrimToIO $  f tl buf buflen arg ))
