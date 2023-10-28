{-# LANGUAGE CApiFFI #-}
module Tfhe where
    import Data.Int

    foreign import ccall "c/tfhe_functions.h generate_key_pair" generate_key_pair :: Int -> IO ()
    foreign import ccall "c/tfhe_functions.h create_encrypted_16bit_input_node" create_encrypted_16bit_input_node :: Int -> Int -> Int16 -> IO ()
    foreign import ccall "c/tfhe_functions.h compute_16bit_minimum" compute_16bit_minimum :: Int -> Int -> Int -> Int -> IO ()
    foreign import ccall "c/tfhe_functions.h decrypt_16bit_node" decrypt_16bit_node :: Int -> Int -> Int16