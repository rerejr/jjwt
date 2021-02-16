package io.jsonwebtoken.impl

import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.EncryptionAlgorithms
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

class DefaultJweBuilderTest {

    @Test
    void testBuild() {
        def enc = EncryptionAlgorithms.A128GCM;
        def key = enc.generateKey()

        String jwe = new DefaultJweBuilder()
                .setSubject('joe')
                .encryptWith(enc)
                .withKey(key)
                .compact()

        println jwe
        println new String(Decoders.BASE64URL.decode('eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0'), StandardCharsets.UTF_8)
    }
}
