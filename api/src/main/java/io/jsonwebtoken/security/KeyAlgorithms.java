package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class KeyAlgorithms {

    //prevent instantiation
    private KeyAlgorithms() {
    }

    private static final Class<?> MAC_CLASS = Classes.forName("io.jsonwebtoken.impl.security.MacSignatureAlgorithm");
    private static final String HMAC = "io.jsonwebtoken.impl.security.HmacAesEncryptionAlgorithm";
    private static final Class<?>[] HMAC_ARGS = new Class[]{String.class, MAC_CLASS};

    private static final String GCM = "io.jsonwebtoken.impl.security.GcmAesEncryptionAlgorithm";
    private static final Class<?>[] GCM_ARGS = new Class[]{String.class, int.class};

    private static AeadSymmetricEncryptionAlgorithm<byte[]> hmac(int keyLength) {
        int digestLength = keyLength * 2;
        String name = "A" + keyLength + "CBC-HS" + digestLength;
        SignatureAlgorithm macSigAlg = Classes.newInstance(SignatureAlgorithms.HMAC, SignatureAlgorithms.HMAC_ARGS, name, "HmacSHA" + digestLength, keyLength);
        return Classes.newInstance(HMAC, HMAC_ARGS, name, macSigAlg);
    }

    private static AeadSymmetricEncryptionAlgorithm<byte[]> gcm(int keyLength) {
        String name = "A" + keyLength + "GCM";
        return Classes.newInstance(GCM, GCM_ARGS, name, keyLength);
    }

    /**
     * AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.3">RFC 7518, Section 5.2.3</a>.  This algorithm
     * requires a 256 bit (32 byte) key.
     */
    public static final KeyAlgorithm<SecretKey, KeyRequest<SecretKey>> DIRECT = Classes.newInstance("io.jsonwebtoken.impl.security.DirectKeyAlgorithm");
}
