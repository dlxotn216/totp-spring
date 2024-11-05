package io.taesu.totpspring

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class TotpSpringApplication

fun main(args: Array<String>) {
    runApplication<TotpSpringApplication>(*args)
}
