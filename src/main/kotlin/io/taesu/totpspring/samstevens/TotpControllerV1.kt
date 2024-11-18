package io.taesu.totpspring.samstevens

import dev.samstevens.totp.code.*
import dev.samstevens.totp.qr.QrData
import dev.samstevens.totp.qr.ZxingPngQrGenerator
import dev.samstevens.totp.secret.DefaultSecretGenerator
import dev.samstevens.totp.time.SystemTimeProvider
import dev.samstevens.totp.time.TimeProvider
import io.taesu.totpspring.User
import jakarta.annotation.PostConstruct
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
class TotpControllerV1 {
    private val timeProvider: TimeProvider = SystemTimeProvider()

    // or NtpTimeProvider("pool.ntp.org") // NTP 서버를 사용하여 시간 동기화
    private val hashingAlgorithm = HashingAlgorithm.SHA256

    // SHA-256은 google authenticator 미지원이라고 하는데 잘 됨 (https://github.com/samdjstevens/java-totp/issues/30)
    // val hashingAlgorithm = HashingAlgorithm.SHA1
    private val digit = 6
    private val codeGenerator: CodeGenerator = DefaultCodeGenerator(hashingAlgorithm, digit)

    private val otpTimePeriod = 30                      // OTP 생성 주기
    private val allowedTimePeriodDiscrepancy = 1        // 허용할 오차 범위
    private val verifier: CodeVerifier = DefaultCodeVerifier(codeGenerator, timeProvider).apply {
        this.setTimePeriod(otpTimePeriod)
        this.setAllowedTimePeriodDiscrepancy(allowedTimePeriodDiscrepancy)
    }

    val userRepository: MutableMap<String, User> = mutableMapOf()

    @PostConstruct
    fun init() {
        listOf(
            User("taesu@demo.io", DefaultSecretGenerator().generate()),
            User("user2", DefaultSecretGenerator().generate()),
            User("user3", DefaultSecretGenerator().generate()),
        ).associateWith {
            userRepository[it.id] = it
        }.run {
            println("User initialized: $this")
        }
    }

    @GetMapping("/api/v1/generate-qr-codes", params = ["type=totp"])
    fun generateQrCode(@RequestParam userId: String): ResponseEntity<ByteArray> {
        val zxingPngQrGenerator = ZxingPngQrGenerator()
        val user = userRepository[userId]!!
        val qrData = generateQrCode(user)
        return ResponseEntity.ok()
            .headers {
                it.contentType = MediaType.IMAGE_PNG
            }
            .body(zxingPngQrGenerator.generate(qrData))
    }

    fun generateQrCode(user: User): QrData {
        return QrData.Builder()
            .secret(user.secret)
            .label(user.id)
            .issuer("Taesu")
            .algorithm(hashingAlgorithm)
            .digits(digit)
            .period(otpTimePeriod)
            .build()
    }

    @PostMapping("/api/v1/verify", params = ["type=totp"])
    fun verify(@RequestBody request: TotpVerifyRequest): Boolean {
        val user = userRepository[request.userId]!!
        return verifier.isValidCode(user.secret, request.otp)
    }

    class TotpVerifyRequest(
        val userId: String,
        val otp: String,
    )
}
