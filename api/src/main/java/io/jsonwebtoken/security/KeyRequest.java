package io.jsonwebtoken.security;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyRequest<T extends Key> {

    T getKey();

}
