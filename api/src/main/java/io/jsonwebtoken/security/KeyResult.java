package io.jsonwebtoken.security;

import javax.crypto.SecretKey;
import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyResult {

    SecretKey getKey();

    byte[] getEncryptedKey();

    Map<String,?> getHeaderParams();
}
