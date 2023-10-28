module Main where
    import Tfhe

    main = do
        let ctx = 3
        ($ ctx) generate_key_pair
        ($ ctx) create_encrypted_16bit_input_node 1 7
        ($ ctx) create_encrypted_16bit_input_node 2 42
        ($ ctx) compute_16bit_minimum 3 1 2

        let result = ($ ctx) decrypt_16bit_node 3
        putStrLn $ "Result is " ++ show result

