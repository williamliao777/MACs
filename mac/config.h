//
// Created by william on 2022/4/3.
//

#ifndef CMAC_CONFIG_H
#define CMAC_CONFIG_H

/** need to choose which AES implementation to run **/
#define gladman_cmac
//#define tiny_cmac
//#define mbedtls_cmac

/** AES constants **/
#define AES_BLOCK_SIZE_BITS 128
#define AES_BLOCK_SIZE_BYTES (AES_BLOCK_SIZE_BITS/8)

#endif

