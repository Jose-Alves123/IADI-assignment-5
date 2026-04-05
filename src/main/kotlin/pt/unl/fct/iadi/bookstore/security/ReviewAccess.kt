package pt.unl.fct.iadi.bookstore.security

import java.util.UUID
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import pt.unl.fct.iadi.bookstore.service.BookstoreService

@Component("reviewAccess")
class ReviewAccess(private val bookstoreService: BookstoreService) {
    fun canEditReview(isbn: String, reviewId: UUID, authentication: Authentication?): Boolean {
        val review = bookstoreService.findReview(isbn, reviewId) ?: return true
        val username = authentication?.name ?: return false
        return review.author == username
    }

    fun canDeleteReview(isbn: String, reviewId: UUID, authentication: Authentication?): Boolean {
        val review = bookstoreService.findReview(isbn, reviewId) ?: return true
        val username = authentication?.name ?: return false
        val isAdmin = authentication.authorities.any { it.authority == "ROLE_ADMIN" }
        return review.author == username || isAdmin
    }
}
