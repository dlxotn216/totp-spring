package io.taesu.totpspring.kotlinontimepassword

import com.google.zxing.BarcodeFormat
import com.google.zxing.client.j2se.MatrixToImageWriter
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import dev.turingcomplete.kotlinonetimepassword.*
import io.taesu.totpspring.User
import io.taesu.totpspring.samstevens.TotpControllerV1.TotpVerifyRequest
import jakarta.annotation.PostConstruct
import org.apache.commons.codec.binary.Base32
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.io.ByteArrayOutputStream
import java.time.Instant
import java.util.concurrent.TimeUnit

/**
 * Created by itaesu on 2024. 11. 5..
 *
 * @author Lee Tae Su
 * @version totp-spring
 * @since totp-spring
 */
@RestController
class TotpControllerV2 {
    private val log = LoggerFactory.getLogger(this::class.java)
    private val otpTimePeriod = 30L // OTP 생성 주기
    private val allowedTimePeriodDiscrepancy = 1        // 허용할 오차 범위
    private val writer = QRCodeWriter()
    private val config = TimeBasedOneTimePasswordConfig(
        codeDigits = 6,
        hmacAlgorithm = HmacAlgorithm.SHA256,
        timeStep = otpTimePeriod,
        timeStepUnit = TimeUnit.SECONDS
    )
    private val userRepository: MutableMap<String, User> = mutableMapOf()

    @PostConstruct
    fun init() {
        listOf(
            User(
                "taesu@demo.io",
                Base32().encodeToString(RandomSecretGenerator().createRandomSecret(HmacAlgorithm.SHA256))
            ),
            User("user2", Base32().encodeToString(RandomSecretGenerator().createRandomSecret(HmacAlgorithm.SHA256))),
            User("user3", Base32().encodeToString(RandomSecretGenerator().createRandomSecret(HmacAlgorithm.SHA256))),
        ).associateWith {
            userRepository[it.id] = it
        }.run {
            println("User initialized: $this")
        }
    }

    @GetMapping("/api/v2/generate-qr-codes", params = ["type=totp"])
    fun generateQrCode(@RequestParam userId: String): ResponseEntity<ByteArray> {
        val user = userRepository[userId]!!
        val qrCodeImageBytes = generateQrCode(user)
        return ResponseEntity.ok()
            .headers {
                it.contentType = MediaType.IMAGE_PNG
            }
            .body(qrCodeImageBytes)
    }

    fun generateQrCode(user: User): ByteArray {
        val qrCodeUri = OtpAuthUriBuilder
            // OtpAuthUriBuilder에서 파라미터 URL 인코딩을 하지 않기에 secrets byte를 인코딩 함
            .forTotp(Base32().encode(Base32().decode(user.secret)))
            .label(user.id, "Taesu V2")   // URL 인코딩 함
            .issuer("Taesu V2")           // URL 인코딩 함
            .algorithm(HmacAlgorithm.SHA256)
            .period(30, TimeUnit.SECONDS)
            .digits(6)
            .buildToString()
        log.info("QR Code URI: $qrCodeUri")
        val bitMatrix: BitMatrix = writer.encode(qrCodeUri, BarcodeFormat.QR_CODE, 350, 350)
        return ByteArrayOutputStream().use {
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", it)
            it.toByteArray()
        }
    }

    @PostMapping("/api/v2/verify", params = ["type=totp"])
    fun verify(@RequestBody request: TotpVerifyRequest): Boolean {
        val user = userRepository[request.userId]!!
        val timeBasedOneTimePasswordGenerator = TimeBasedOneTimePasswordGenerator(Base32().decode(user.secret), config)
        val now = Instant.now()
        return (-allowedTimePeriodDiscrepancy..allowedTimePeriodDiscrepancy).any {
            timeBasedOneTimePasswordGenerator.isValid(request.otp, now.plusSeconds(it * otpTimePeriod))
        }
    }
}
