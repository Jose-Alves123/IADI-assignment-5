package pt.unl.fct.iadi.bookstore.security

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletResponse
import java.nio.charset.StandardCharsets
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import pt.unl.fct.iadi.bookstore.controller.dto.ErrorResponse

@Component
class SecurityErrorResponseWriter(private val objectMapper: ObjectMapper) {
    fun writeUnauthorized(response: HttpServletResponse, message: String) {
        write(response, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", message)
    }

    fun writeForbidden(response: HttpServletResponse, message: String = "Forbidden") {
        write(response, HttpStatus.FORBIDDEN, "FORBIDDEN", message)
    }

    private fun write(
            response: HttpServletResponse,
            status: HttpStatus,
            error: String,
            message: String
    ) {
        if (response.isCommitted) {
            return
        }

        response.status = status.value()
        response.characterEncoding = StandardCharsets.UTF_8.name()
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        objectMapper.writeValue(response.outputStream, ErrorResponse(error, message))
    }
}
