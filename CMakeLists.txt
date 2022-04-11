cmake_minimum_required(VERSION 3.21)
project(MACs C)

ADD_LIBRARY(CMAC STATIC
        aes/aes.c
        mac/cmac/cmac.c
        mac/cmac/utils.c
        aes/gladman/aestst.c
        aes/gladman/aesaux.c
        aes/gladman/aescrypt.c
        aes/gladman/aeskey.c
        aes/gladman/aestab.c
        aes/tiny_aes/aes.c
        aes/mbedtls/aes.c
        )

#ADD_LIBRARY( HMAC STATIC
#        mac/hmac/hmac_sha256.c
#        sha/gladman/sha2.c
#        sha/saddi/sha256.c
#        sha/mbedtls/sha256.c
#        )

set(CMAKE_C_STANDARD 99)

add_executable(MACs mac/cmac/main.c)

TARGET_LINK_LIBRARIES(MACs
        CMAC)