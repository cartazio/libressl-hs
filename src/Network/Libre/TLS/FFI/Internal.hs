{-# LANGUAGE ForeignFunctionInterface #-}

module Network.Libre.TLS.FFI.Internal where


import Foreign.C.Types
import Foreign.Ptr
import Foreign.C.String
import Data.Word(Word32(..), Word8(..))

{-
--   #define TLS_WANT_POLLIN    -2
--   #define TLS_WANT_POLLOUT  -3

-}
--struct tls;
data LibTLSContext
newtype TLSPtr = TheTLSPTR (Ptr LibTLSContext)

--struct tls_config;
data LibTLSConfig
newtype TLSConfigPtr = TheTLSConfigPtr (Ptr LibTLSConfig)

newtype LibreFD = LibreFD { unLibreFD :: CInt }

newtype LibreSocket = LibreSocket { unLibreSocket :: CInt }

--int tls_init(void);
foreign import ccall safe "tls_init" tls_init_c :: IO CInt

--const char *tls_error(struct tls *_ctx);
foreign import ccall safe "tls_error" tls_error_c  :: TLSPtr -> IO CString
-- the result string is NULL / EMPTY if there is no error condition?
-- at least for some non null strings, they live in the static "data"
-- section of the underlying libressl library

--struct tls_config *tls_config_new(void);
foreign import ccall safe "tls_config_new" tls_config_new_c :: IO TLSConfigPtr

--void tls_config_free(struct tls_config *_config);
foreign import ccall safe "tls_config_free" tls_config_free_c :: TLSConfigPtr -> IO ()

--int tls_config_set_ca_file(struct tls_config *_config, const char *_ca_file);
foreign import ccall safe "tls_config_set_ca_file" tls_config_set_ca_file_c ::  TLSConfigPtr -> CString -> IO CInt

--int tls_config_set_ca_path(struct tls_config *_config, const char *_ca_path);
foreign import ccall safe "tls_config_set_ca_path" tls_config_set_ca_path_c :: TLSConfigPtr -> CString -> IO CInt

--int tls_config_set_ca_mem(struct tls_config *_config, const uint8_t *_ca,
--    size_t _len);
foreign import ccall safe "tls_config_set_ca_mem" tls_config_set_ca_mem_c :: TLSConfigPtr -> Ptr CChar -> CSize -> IO CInt
-- csize len should match buffer/array length

--int tls_config_set_cert_file(struct tls_config *_config,
--    const char *_cert_file);
foreign import ccall safe "tls_config_set_cert_file" tls_config_set_cert_file_c :: TLSConfigPtr -> CString -> IO CInt

--int tls_config_set_cert_mem(struct tls_config *_config, const uint8_t *_cert,
--    size_t _len);
foreign import ccall safe "tls_config_set_cert_mem" tls_config_set_cert_mem_c :: TLSConfigPtr -> Ptr CChar -> CSize -> IO CInt

--int tls_config_set_ciphers(struct tls_config *_config, const char *_ciphers);
foreign import ccall safe "tls_config_set_ciphers" tls_config_set_ciphers_c :: TLSConfigPtr -> CString -> IO CInt

--int tls_config_set_dheparams(struct tls_config *_config, const char *_params);
foreign import ccall safe "tls_config_set_dheparams" tls_config_set_dheparams_c :: TLSConfigPtr -> CString -> IO CInt

--int tls_config_set_ecdhecurve(struct tls_config *_config, const char *_name);
foreign import ccall safe "tls_config_set_ecdhecurve" tls_config_set_ecdhecurve_c :: TLSConfigPtr -> CString -> IO CInt

--int tls_config_set_key_file(struct tls_config *_config, const char *_key_file);
foreign import ccall safe "tls_config_set_key_file" tls_config_set_key_file_c :: TLSConfigPtr -> CString -> IO CInt

--int tls_config_set_key_mem(struct tls_config *_config, const uint8_t *_key,
--    size_t _len);
foreign import ccall safe "tls_config_set_key_mem" tls_config_set_key_mem_c :: TLSConfigPtr -> Ptr CChar -> CSize -> IO CInt

--void tls_config_set_protocols(struct tls_config *_config, uint32_t _protocols);
foreign import ccall safe "tls_config_set_protocols" tls_config_set_protocols_c :: TLSConfigPtr -> Word32 -> IO ()

--void tls_config_set_verify_depth(struct tls_config *_config, int _verify_depth);
foreign import ccall safe "tls_config_set_verify_depth" tls_config_set_verify_depth_c  :: TLSConfigPtr -> CInt -> IO ()

----void tls_config_prefer_ciphers_client(struct tls_config *_config);
--foreign import ccall safe "tls_config_prefer_ciphers_client" tls_config_prefer_ciphers_client_c :: TLSConfigPtr -> IO ()
--- bad security, thus we dont provide it :)


--void tls_config_prefer_ciphers_server(struct tls_config *_config);
foreign import ccall safe "tls_config_prefer_ciphers_server" tls_config_prefer_ciphers_server_c :: TLSConfigPtr -> IO ()

--void tls_config_insecure_noverifycert(struct tls_config *_config);
foreign import ccall safe "tls_config_insecure_noverifycert" tls_config_insecure_noverifycert_foot_gun_testingOnly_c :: TLSConfigPtr -> IO ()

--void tls_config_insecure_noverifyname(struct tls_config *_config);
foreign import ccall safe "tls_config_insecure_noverifyname" tls_config_insecure_noverifyname_foot_gun_testingOnly_c :: TLSConfigPtr -> IO ()

--void tls_config_insecure_noverifytime(struct tls_config *_config);
foreign import ccall safe "tls_config_insecure_noverifytime" tls_config_insecure_noverifytime_footGun_testing_only_C :: TLSConfigPtr -> IO ()

--void tls_config_verify(struct tls_config *_config);
foreign import ccall safe "tls_config_verify" tls_config_verify_c :: TLSConfigPtr -> IO ()

--void tls_config_verify_client(struct tls_config *_config);
foreign import ccall safe "tls_config_verify_client" tls_config_verify_client_c :: TLSConfigPtr -> IO ()

--void tls_config_verify_client_optional(struct tls_config *_config);
foreign import ccall safe "tls_config_verify_client_optional" tls_config_verify_client_optional_c :: TLSConfigPtr -> IO ()

--void tls_config_clear_keys(struct tls_config *_config);
foreign import ccall safe "tls_config_clear_keys" tls_config_clear_keys_c :: TLSConfigPtr -> IO ()

--int tls_config_parse_protocols(uint32_t *_protocols, const char *_protostr);
foreign import ccall safe "tls_config_parse_protocols" tls_config_parse_protocols_c :: Ptr Word32 -> CString -> IO CInt
--- Ptr Word32 holds a bitset of protocols, its part of the output

--struct tls *tls_client(void);
foreign import ccall safe "tls_client" allocate_fresh_tls_client_context_c :: IO TLSPtr

--struct tls *tls_server(void);
foreign import ccall safe "tls_server" allocate_fresh_tls_server_context_c :: IO TLSPtr

--int tls_configure(struct tls *_ctx, struct tls_config *_config);
foreign import ccall safe "tls_configure" tls_configure_c :: TLSPtr -> TLSConfigPtr -> IO CInt

--void tls_reset(struct tls *_ctx);
--foreign import ccall safe  "tls_reset" tls_reset_we_aren't_sure_why_this_is_exported_c :: TLSPtr -> ()
--- we dont import/link this for this for now because theres no sane way to use this
-- everrrrr, unless part of a tls_free  invocation


--void tls_free(struct tls *_ctx);
foreign import ccall safe  "tls_free" tls_free_c :: TLSPtr -> IO ()

--int tls_accept_fds(struct tls *_ctx, struct tls **_cctx, int _fd_read,
--    int _fd_write);
foreign import ccall safe  "tls_accept_fds" tls_accept_fds_c :: TLSPtr -> Ptr TLSPtr -> LibreFD -> LibreFD -> IO CInt


--int tls_accept_socket(struct tls *_ctx, struct tls **_cctx, int _socket);
foreign import ccall safe "tls_accept_socket" tls_accept_socket_c :: TLSPtr -> Ptr TLSPtr -> LibreSocket -> IO CInt

--int tls_connect(struct tls *_ctx, const char *_host, const char *_port);
foreign import ccall safe "tls_connect" tls_connect_c :: TLSPtr -> CString -> CString -> IO CInt

--int tls_connect_fds(struct tls *_ctx, int _fd_read, int _fd_write,
--    const char *_servername);
foreign import ccall safe "tls_connect_fds" tls_connect_fds_c :: TLSPtr -> LibreFD -> LibreFD -> CString -> IO CInt

--int tls_connect_servername(struct tls *_ctx, const char *_host,
--    const char *_port, const char *_servername);
foreign import ccall safe "tls_connect_servername" tls_connect_servername_c :: TLSPtr -> CString -> CString -> CString -> IO CInt

--int tls_connect_socket(struct tls *_ctx, int _s, const char *_servername);
foreign import ccall safe "tls_connect_socket" tls_connect_socket_c :: TLSPtr -> LibreSocket -> CString -> IO CInt

--int tls_handshake(struct tls *_ctx);
foreign import ccall safe "tls_handshake" tls_handshake_c :: TLSPtr -> IO CInt

--ssize_t tls_read(struct tls *_ctx, void *_buf, size_t _buflen);
foreign import ccall safe "tls_read" tls_read_c :: TLSPtr -> Ptr Word8 -> CSize -> IO CSize

--ssize_t tls_write(struct tls *_ctx, const void *_buf, size_t _buflen);
foreign import ccall safe "tls_write" tls_write_c :: TLSPtr -> Ptr Word8 -> CSize -> IO CSize

--int tls_close(struct tls *_ctx);
foreign import ccall safe "tls_close" tls_close_c :: TLSPtr -> IO CInt

--int tls_peer_cert_provided(struct tls *ctx);
foreign import ccall safe "tls_peer_cert_provided" tls_peer_cert_provided_c :: TLSPtr -> IO CInt

--int tls_peer_cert_contains_name(struct tls *ctx, const char *name);
foreign import ccall safe "tls_peer_cert_contains_name" tls_peer_cert_contains_name_c :: TLSPtr -> CString -> IO CInt

--const char * tls_peer_cert_hash(struct tls *_ctx);
foreign import ccall safe "tls_peer_cert_hash" tls_peer_cert_hash_c :: TLSPtr -> IO CString

--const char * tls_peer_cert_issuer(struct tls *ctx);
foreign import ccall safe "tls_peer_cert_issuer" tls_peer_cert_issuer_c :: TLSPtr -> IO CString

--const char * tls_peer_cert_subject(struct tls *ctx);
foreign import ccall safe "tls_peer_cert_subject" tls_peer_cert_subject_c :: TLSPtr -> IO CString

--time_t  tls_peer_cert_notbefore(struct tls *ctx);
foreign import ccall safe "tls_peer_cert_notbefore" tls_peer_cert_notbefore_c :: TLSPtr -> IO CTime

--time_t  tls_peer_cert_notafter(struct tls *ctx);
foreign import ccall safe "tls_peer_cert_notafter" tls_peer_cert_notafter_c :: TLSPtr -> IO CTime

--const char * tls_conn_version(struct tls *ctx);
foreign import ccall safe "tls_conn_version" tls_conn_version_c :: TLSPtr -> IO CString

--const char * tls_conn_cipher(struct tls *ctx);
foreign import ccall safe "tls_conn_cipher" tls_conn_cipher :: TLSPtr -> IO CString

--uint8_t *tls_load_file(const char *_file, size_t *_len, char *_password);
foreign import ccall safe "tls_load_file" tls_load_file :: CString -> CSize -> CString -> IO CString