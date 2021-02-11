<?php

declare(strict_types=1);

namespace Huhushow\GameCenterIdVerifier;

class GameCenterIdVerifier
{
    const GAMEKIT_PKEY_ALGO = OPENSSL_ALGO_SHA256;

    /**
     * convert apple cer public key to pem format
     * @param string $cer
     */
    public static function cerToPem(string $cer): string
    {
        $pem = chunk_split(\base64_encode($cer), 64, "\n");
        $pem = "-----BEGIN CERTIFICATE-----\n" .
            $pem .
            "-----END CERTIFICATE-----\n";
        return $pem;
    }

    /**
     * set a timestamp in big-endian Uint64 format
     * @param int $timestamp unix-timestamp string 
     */
    public static function timestampToBigEndian(int $timestamp): string
    {
        return pack('J', $timestamp);
    }

    public static function verifyData(
        string $signature,
        string $pem,
        string $payerId,
        string $bundleId,
        int $timestamp,
        string $salt
    ): bool {
        $payerId = utf8_encode($payerId);
        $bundleId = utf8_encode($bundleId);
        $timestampStr = self::timestampToBigEndian($timestamp);
        $salt = base64_decode($salt);
        $signature = base64_decode($signature);
        $data = $payerId . $bundleId . $timestampStr . $salt;

        if (($pubkeyId = openssl_pkey_get_public($pem)) === false) {
            return false;
        }
        $result = openssl_verify(
            $data,
            $signature,
            $pubkeyId,
            self::GAMEKIT_PKEY_ALGO
        );

        openssl_free_key($pubkeyId);

        if ($result === 1) {
            return true;
        }
        return false;
    }

    /**
     * @param string $signature
     * @param string $pem
     * @param string $hash sha256 hash binary that already hashed from other side
     * @return boolean
     */
    public static function verifyHash(
        string $signature,
        string $pem,
        string $hash
    ): bool {
        $signature = base64_decode($signature);
        if (($pubkeyId = openssl_pkey_get_public($pem)) === false) {
            return false;
        }

        $keyLength = openssl_pkey_get_details($pubkeyId)['bits'] / 8;
        $padLength = $keyLength - 32;

        if (!openssl_public_decrypt(
            $signature, 
            $compare, 
            $pubkeyId, 
            OPENSSL_NO_PADDING
        )
        ) {
            return false;
        }

        $compare = substr($compare, $padLength);
        return hash_equals($hash, $compare);
    }
}