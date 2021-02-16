package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.KeyRequest;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EncryptKeyRequest<K extends Key> extends KeyRequest<K>, CryptoRequest<SecretKey, K> {
}
