package io.jsonwebtoken.security;

import io.jsonwebtoken.Named;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyAlgorithm<K extends Key, R extends KeyRequest<K>> extends Named {

    KeyResult getKey(R request);

}
