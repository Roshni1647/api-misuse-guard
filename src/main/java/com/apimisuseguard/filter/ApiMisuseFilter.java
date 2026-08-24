package com.apimisuseguard.filter;

import com.apimisuseguard.model.SecurityEvent;
import com.apimisuseguard.service.SecurityEventService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class ApiMisuseFilter extends OncePerRequestFilter {

    private final SecurityEventService securityEventService;

    /*
     * Stores request counts per client IP.
     *
     * Example:
     *
     * 127.0.0.1 -> 14 requests
     */
    private final Map<String, RequestCounter> requestCounters
            = new ConcurrentHashMap<>();


    public ApiMisuseFilter(
            SecurityEventService securityEventService) {

        this.securityEventService = securityEventService;
    }


    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {


        /*
         * =====================================================
         * ENDPOINT
         * =====================================================
         */

        String endpoint = request.getRequestURI();


        /*
         * Some application routes should not
         * participate in API misuse monitoring.
         */
        if (shouldIgnore(endpoint)) {

            filterChain.doFilter(
                    request,
                    response
            );

            return;
        }


        /*
         * =====================================================
         * AUTOMATIC REQUEST INFORMATION
         * =====================================================
         */

        String ipAddress =
                getClientIp(request);


        String method =
                request.getMethod();


        String role =
                getSessionValue(
                        request,
                        "role",
                        "GUEST"
                );


        String username =
                getSessionValue(
                        request,
                        "username",
                        "anonymous"
                );


        /*
         * Automatically calculate how many
         * requests this IP made in the
         * current 60-second window.
         */
        int requestsPerMinute =
                calculateRequestsPerMinute(
                        ipAddress
                );


        /*
         * Example:
         *
         * /demo/search?q=phone
         *
         * Query string:
         *
         * q=phone
         */
        String queryString =
                decodeQuery(
                        request.getQueryString()
                );


        /*
         * =====================================================
         * RULE 1
         *
         * SUSPICIOUS INPUT
         * =====================================================
         */

        if (isSuspicious(queryString)) {

            SecurityEvent event =
                    createRequestEvent(
                            ipAddress,
                            username,
                            endpoint,
                            method,
                            role,
                            requestsPerMinute
                    );


            event.setEventType(
                    "SUSPICIOUS_INPUT"
            );


            event.setRiskLevel(
                    "CRITICAL"
            );


            event.setExplanation(
                    "Request contained an input pattern "
                    + "commonly associated with an "
                    + "SQL-injection attempt."
            );


            event.setAction(
                    "BLOCKED"
            );


            event.setHttpStatus(
                    400
            );


            securityEventService
                    .recordEvent(event);


            response.sendError(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "Suspicious request blocked"
            );


            return;
        }


        /*
         * =====================================================
         * RULE 2
         *
         * ADMIN-ONLY ENDPOINT ACCESS
         * =====================================================
         *
         * These require ADMIN:
         *
         * /admin/**
         *
         * /security-dashboard
         */

        boolean adminProtectedEndpoint =
                endpoint.startsWith("/admin")
                || endpoint.equals(
                        "/security-dashboard"
                );


        if (adminProtectedEndpoint
                && !"ADMIN".equals(role)) {


            SecurityEvent event =
                    createRequestEvent(
                            ipAddress,
                            username,
                            endpoint,
                            method,
                            role,
                            requestsPerMinute
                    );


            event.setEventType(
                    "UNAUTHORIZED_ACCESS"
            );


            event.setRiskLevel(
                    "CRITICAL"
            );


            event.setExplanation(
                    "Authenticated role "
                    + role
                    + " attempted to access "
                    + "ADMIN-only endpoint "
                    + endpoint
                    + "."
            );


            event.setAction(
                    "BLOCKED"
            );


            event.setHttpStatus(
                    403
            );


            securityEventService
                    .recordEvent(event);


            response.sendError(
                    HttpServletResponse.SC_FORBIDDEN,
                    "Unauthorized API access"
            );


            return;
        }


        /*
         * =====================================================
         * RULE 3
         *
         * RATE MISUSE
         * =====================================================
         *
         * Limit:
         *
         * 30 monitored requests
         * per IP
         * per 60 seconds.
         */

        if (requestsPerMinute > 30) {


            SecurityEvent event =
                    createRequestEvent(
                            ipAddress,
                            username,
                            endpoint,
                            method,
                            role,
                            requestsPerMinute
                    );


            event.setEventType(
                    "RATE_MISUSE"
            );


            event.setRiskLevel(
                    "HIGH"
            );


            event.setExplanation(
                    "Client exceeded the configured "
                    + "limit of 30 requests per minute. "
                    + "Observed request count: "
                    + requestsPerMinute
                    + "."
            );


            event.setAction(
                    "BLOCKED"
            );


            event.setHttpStatus(
                    429
            );


            securityEventService
                    .recordEvent(event);


            response.sendError(
                    429,
                    "Rate misuse detected"
            );


            return;
        }


        /*
         * =====================================================
         * SAFE REQUEST
         * =====================================================
         *
         * No misuse rule matched.
         *
         * Let the request continue normally.
         */

        filterChain.doFilter(
                request,
                response
        );
    }


    /*
     * =====================================================
     * CLIENT IP DETECTION
     * =====================================================
     *
     * For this localhost project we deliberately
     * use the TCP client address supplied by Tomcat.
     *
     * We DO NOT blindly trust X-Forwarded-For.
     *
     * Examples:
     *
     * IPv4 localhost:
     * 127.0.0.1
     *
     * IPv6 localhost:
     * ::1
     *
     * Windows may also show:
     * 0:0:0:0:0:0:0:1
     *
     * For a cleaner demo, all localhost variants
     * are displayed as:
     *
     * 127.0.0.1
     */

    private String getClientIp(
            HttpServletRequest request) {


        String remoteAddress =
                request.getRemoteAddr();


        if (remoteAddress == null
                || remoteAddress.isBlank()) {

            return "UNKNOWN";
        }


        /*
         * Normalize IPv6 localhost.
         */
        if ("::1".equals(remoteAddress)
                ||
                "0:0:0:0:0:0:0:1"
                        .equals(remoteAddress)) {

            return "127.0.0.1";
        }


        return remoteAddress;
    }


    /*
     * =====================================================
     * READ SESSION ATTRIBUTE
     * =====================================================
     *
     * Example after login:
     *
     * username = user
     * role     = USER
     *
     * Without a valid session:
     *
     * username = anonymous
     * role     = GUEST
     */

    private String getSessionValue(
            HttpServletRequest request,
            String attribute,
            String defaultValue) {


        HttpSession session =
                request.getSession(false);


        if (session == null) {

            return defaultValue;
        }


        Object value =
                session.getAttribute(
                        attribute
                );


        if (value == null) {

            return defaultValue;
        }


        return value.toString();
    }


    /*
     * =====================================================
     * CREATE COMMON REQUEST SECURITY EVENT
     * =====================================================
     */

    private SecurityEvent createRequestEvent(
            String ipAddress,
            String username,
            String endpoint,
            String method,
            String role,
            int requestsPerMinute) {


        SecurityEvent event =
                new SecurityEvent();


        event.setIpAddress(
                ipAddress
        );


        event.setUsername(
                username
        );


        event.setEndpoint(
                endpoint
        );


        event.setMethod(
                method
        );


        event.setActualRole(
                role
        );


        /*
         * For filter-based HTTP events,
         * the current authenticated role
         * is also considered the requested role.
         *
         * LoginController separately handles
         * USER → ADMIN role mismatch.
         */
        event.setRequestedRole(
                role
        );


        event.setRequestsPerMinute(
                requestsPerMinute
        );


        return event;
    }


    /*
     * =====================================================
     * ROUTES EXCLUDED FROM MONITORING
     * =====================================================
     */

    private boolean shouldIgnore(
            String endpoint) {


        return endpoint.equals("/")
                || endpoint.equals("/login")
                || endpoint.equals("/logout")
                || endpoint.equals("/events/stream")
                || endpoint.equals("/error")
                || endpoint.equals("/favicon.ico")
                || endpoint.startsWith("/css/")
                || endpoint.startsWith("/js/")
                || endpoint.startsWith("/images/");
    }


    /*
     * =====================================================
     * SUSPICIOUS QUERY DETECTOR
     * =====================================================
     *
     * Educational rule-based detection only.
     *
     * This is NOT a complete SQL injection
     * prevention solution.
     */

    private boolean isSuspicious(
            String input) {


        if (input == null
                || input.isBlank()) {

            return false;
        }


        String value =
                input.toLowerCase();


        return value.contains(
                        "union select"
                )
                ||
                value.contains(
                        "' or 1=1"
                )
                ||
                value.contains(
                        "' or '1'='1"
                )
                ||
                value.contains(
                        "\" or \"1\"=\"1"
                );
    }


    /*
     * =====================================================
     * URL-DECODE QUERY
     * =====================================================
     *
     * Browser URLs often encode characters.
     *
     * Example:
     *
     * %27
     *
     * becomes:
     *
     * '
     */

    private String decodeQuery(
            String query) {


        if (query == null) {

            return null;
        }


        try {


            return URLDecoder.decode(
                    query,
                    StandardCharsets.UTF_8
            );


        } catch (Exception e) {


            return query;
        }
    }


    /*
     * =====================================================
     * REQUESTS-PER-MINUTE CALCULATION
     * =====================================================
     */

    private int calculateRequestsPerMinute(
            String ipAddress) {


        long currentTime =
                Instant.now()
                        .toEpochMilli();


        RequestCounter counter =
                requestCounters
                        .computeIfAbsent(
                                ipAddress,
                                key ->
                                        new RequestCounter()
                        );


        synchronized (counter) {


            /*
             * Start a new window after
             * 60 seconds.
             */
            if (currentTime
                    - counter.windowStart
                    >= 60_000) {


                counter.windowStart =
                        currentTime;


                counter.count = 0;
            }


            counter.count++;


            return counter.count;
        }
    }


    /*
     * =====================================================
     * REQUEST COUNTER
     * =====================================================
     */

    private static class RequestCounter {


        private long windowStart =
                Instant.now()
                        .toEpochMilli();


        private int count = 0;
    }
}