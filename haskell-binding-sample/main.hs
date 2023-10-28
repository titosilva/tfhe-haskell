{-# LANGUAGE CApiFFI #-}
module Main where
    foreign import ccall "functions.h next" next :: Int -> Int

    main = do
        let n = next 4
        print n

