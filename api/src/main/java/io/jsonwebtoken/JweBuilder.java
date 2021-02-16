package io.jsonwebtoken;

import io.jsonwebtoken.security.AeadSymmetricEncryptionAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface JweBuilder extends JwtBuilder<JweBuilder> {

    JweBuilder encryptWith(AeadSymmetricEncryptionAlgorithm<byte[]> enc);

    JweBuilder withKey(SecretKey key);

    <K extends Key, R extends KeyRequest<K>> JweBuilder withKeyFrom(K key, KeyAlgorithm<K, R> alg);
}
