package io.taesu.totpspring

/**
 * Created by itaesu on 2024. 11. 5..
 *
 * @author Lee Tae Su
 * @version totp-spring
 * @since totp-spring
 */
data class User(
    val id: String,
    val secret: String,
)

data class User2(
    val id: String,
    val secret: ByteArray,
)

