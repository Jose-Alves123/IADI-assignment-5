package pt.unl.fct.iadi.bookstore.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class ApiTokenFilter(
        private val apiTokenService: ApiTokenService,
        private val errorWriter: SecurityErrorResponseWriter
) : OncePerRequestFilter() {

    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val path = request.requestURI
        return path == "/swagger-ui.html" ||
                path.startsWith("/swagger-ui/") ||
                path.startsWith("/v3/api-docs") ||
                path.startsWith("/webjars/")
    }

    override fun doFilterInternal(
            request: HttpServletRequest,
            response: HttpServletResponse,
            filterChain: FilterChain
    ) {
        val token = request.getHeader("X-Api-Token")
        if (!apiTokenService.isValid(token)) {
            errorWriter.writeUnauthorized(response, "Missing or invalid X-Api-Token")
            return
        }

        request.setAttribute("apiAppName", apiTokenService.appNameFor(token))
        filterChain.doFilter(request, response)
    }
}
