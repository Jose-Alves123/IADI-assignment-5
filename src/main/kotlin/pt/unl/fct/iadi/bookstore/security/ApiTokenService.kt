package pt.unl.fct.iadi.bookstore.security

import org.springframework.stereotype.Component

@Component
class ApiTokenService {
    private val tokensToApps =
            mapOf(
                    "token-catalog-abc123" to "catalog-app",
                    "token-mobile-def456" to "mobile-app",
                    "token-web-ghi789" to "web-app"
            )

    fun isValid(token: String?): Boolean {
        return token != null && tokensToApps.containsKey(token)
    }

    fun appNameFor(token: String?): String {
        return token?.let { tokensToApps[it] } ?: "unknown"
    }
}
