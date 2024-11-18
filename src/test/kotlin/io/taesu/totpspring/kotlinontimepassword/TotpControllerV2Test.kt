package io.taesu.totpspring.kotlinontimepassword

import dev.turingcomplete.kotlinonetimepassword.HmacAlgorithm
import dev.turingcomplete.kotlinonetimepassword.RandomSecretGenerator
import org.apache.commons.codec.binary.Base32
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Created by itaesu on 2024. 11. 6..
 *
 * @author Lee Tae Su
 * @version totp-spring
 * @since totp-spring
 */
class TotpControllerV2Test {
    @Test
    fun `Base32 문자열로 인코딩 된 secrets은 decode시 원본과 동일하다`() {
        // given
        val secrets: ByteArray = RandomSecretGenerator().createRandomSecret(HmacAlgorithm.SHA256)

        // when
        val encoded: String = Base32().encodeToString(secrets)
        val toByteArray: ByteArray = Base32().decode(encoded)

        // then
        assertThat(toByteArray).isEqualTo(secrets)
    }
}
