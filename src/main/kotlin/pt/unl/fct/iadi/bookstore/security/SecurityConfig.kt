package pt.unl.fct.iadi.bookstore.security

import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType
import io.swagger.v3.oas.annotations.security.SecurityScheme
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.User.withUsername
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@SecurityScheme(name = "basicAuth", type = SecuritySchemeType.HTTP, scheme = "basic")
@SecurityScheme(
        name = "apiToken",
        type = SecuritySchemeType.APIKEY,
        `in` = SecuritySchemeIn.HEADER,
        paramName = "X-Api-Token"
)
class SecurityConfig(
        private val apiTokenFilter: ApiTokenFilter,
        private val requestLoggingFilter: RequestLoggingFilter,
        private val errorWriter: SecurityErrorResponseWriter
) {

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return NoOpPasswordEncoder.getInstance()
    }

    @Bean
    fun userDetailsService(): UserDetailsService {
        return InMemoryUserDetailsManager(
                withUsername("editor1").password("editor1pass").roles("EDITOR").build(),
                withUsername("editor2").password("editor2pass").roles("EDITOR").build(),
                withUsername("admin").password("adminpass").roles("ADMIN").build()
        )
    }

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
                .csrf { it.disable() }
                .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests { authorize ->
                    authorize
                            .requestMatchers(
                                    "/swagger-ui.html",
                                    "/swagger-ui/**",
                                    "/v3/api-docs",
                                    "/v3/api-docs/**",
                                    "/webjars/**"
                            )
                            .permitAll()
                    authorize
                            .requestMatchers(HttpMethod.POST, "/books")
                            .hasAnyRole("EDITOR", "ADMIN")
                    authorize
                            .requestMatchers(HttpMethod.PUT, "/books/*")
                            .hasAnyRole("EDITOR", "ADMIN")
                    authorize
                            .requestMatchers(HttpMethod.PATCH, "/books/*")
                            .hasAnyRole("EDITOR", "ADMIN")
                    authorize.requestMatchers(HttpMethod.DELETE, "/books/*").hasRole("ADMIN")
                    authorize
                            .requestMatchers(HttpMethod.POST, "/books/*/reviews")
                            .hasAnyRole("EDITOR", "ADMIN")
                    authorize
                            .requestMatchers(HttpMethod.PUT, "/books/*/reviews/*")
                            .hasAnyRole("EDITOR", "ADMIN")
                    authorize
                            .requestMatchers(HttpMethod.PATCH, "/books/*/reviews/*")
                            .hasAnyRole("EDITOR", "ADMIN")
                    authorize
                            .requestMatchers(HttpMethod.DELETE, "/books/*/reviews/*")
                            .authenticated()
                    authorize.anyRequest().permitAll()
                }
                .exceptionHandling { exceptions ->
                    exceptions.authenticationEntryPoint { _, response, _ ->
                        errorWriter.writeUnauthorized(response, "Missing or invalid credentials")
                    }
                    exceptions.accessDeniedHandler { _, response, _ ->
                        errorWriter.writeForbidden(response)
                    }
                }
                .addFilterBefore(apiTokenFilter, UsernamePasswordAuthenticationFilter::class.java)
                .addFilterBefore(requestLoggingFilter, ApiTokenFilter::class.java)

        return http.build()
    }
}
