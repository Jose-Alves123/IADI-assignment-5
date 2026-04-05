package pt.unl.fct.iadi.bookstore.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class RequestLoggingFilter(private val apiTokenService: ApiTokenService) : OncePerRequestFilter() {

    private val auditLogger = LoggerFactory.getLogger(RequestLoggingFilter::class.java)

    override fun doFilterInternal(
            request: HttpServletRequest,
            response: HttpServletResponse,
            filterChain: FilterChain
    ) {
        try {
            filterChain.doFilter(request, response)
        } finally {
            val appName = apiTokenService.appNameFor(request.getHeader("X-Api-Token"))
            val authentication = SecurityContextHolder.getContext().authentication
            val principal =
                    if (authentication == null ||
                                    !authentication.isAuthenticated ||
                                    authentication is AnonymousAuthenticationToken
                    ) {
                        "anonymous"
                    } else {
                        authentication.name
                    }

            auditLogger.info(
                    "[{}] [{}] {} {} [{}]",
                    appName,
                    principal,
                    request.method,
                    request.requestURI,
                    response.status
            )
        }
    }
}
