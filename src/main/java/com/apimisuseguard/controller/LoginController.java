package com.apimisuseguard.controller;

import com.apimisuseguard.model.SecurityEvent;
import com.apimisuseguard.service.SecurityEventService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    private final SecurityEventService securityEventService;

    /*
     * Counts failed password attempts.
     *
     * Key example:
     * ::1|user
     */
    private final Map<String, Integer> failedAttempts =
            new ConcurrentHashMap<>();

    public LoginController(
            SecurityEventService securityEventService) {

        this.securityEventService =
                securityEventService;
    }

    /*
     * ========================================
     * HOME PAGE
     * ========================================
     */

    @GetMapping("/")
    public String home() {

        return "login";
    }


    /*
     * ========================================
     * LOGIN
     * ========================================
     */

    @PostMapping("/login")
    public String login(
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam String requestedRole,
            HttpServletRequest request,
            Model model) {

        String ipAddress =
                request.getRemoteAddr();

        username =
                username.trim();

        requestedRole =
                requestedRole.toUpperCase();

        /*
         * Determine the REAL role internally.
         *
         * We DO NOT trust the role selected
         * in the browser.
         */
        String actualRole =
                findActualRole(username);

        String attemptKey =
                ipAddress
                + "|"
                + username.toLowerCase();


        /*
         * ========================================
         * UNKNOWN USERNAME
         * ========================================
         */

        if (actualRole == null) {

            int attempts =
                    incrementFailedAttempts(
                            attemptKey
                    );

            SecurityEvent event =
                    createBaseEvent(
                            ipAddress,
                            username
                    );

            event.setActualRole("UNKNOWN");

            event.setRequestedRole(
                    requestedRole
            );

            event.setEventType(
                    "FAILED_LOGIN"
            );

            event.setRiskLevel(
                    "MEDIUM"
            );

            event.setExplanation(
                    "Authentication failed because "
                    + "the supplied username was not "
                    + "recognized by the demo application."
            );

            event.setAction(
                    "LOGIN_DENIED"
            );

            event.setFailedAttempts(
                    attempts
            );

            event.setHttpStatus(401);

            securityEventService
                    .recordEvent(event);


            checkForBruteForce(
                    ipAddress,
                    username,
                    "UNKNOWN",
                    requestedRole,
                    attempts
            );


            model.addAttribute(
                    "error",
                    "Login denied. Check your credentials and selected role."
            );

            return "login";
        }


        /*
         * ========================================
         * WRONG PASSWORD
         * ========================================
         */

        if (!isPasswordCorrect(
                username,
                password)) {

            int attempts =
                    incrementFailedAttempts(
                            attemptKey
                    );

            SecurityEvent event =
                    createBaseEvent(
                            ipAddress,
                            username
                    );

            event.setActualRole(
                    actualRole
            );

            event.setRequestedRole(
                    requestedRole
            );

            event.setEventType(
                    "FAILED_LOGIN"
            );

            /*
             * Wrong password against ADMIN
             * is treated as more important.
             */
            if ("ADMIN".equals(actualRole)) {

                event.setRiskLevel("HIGH");

                event.setExplanation(
                        "Invalid password supplied while "
                        + "attempting authentication to "
                        + "a privileged ADMIN account."
                );

            } else {

                event.setRiskLevel("MEDIUM");

                event.setExplanation(
                        "Invalid password supplied for "
                        + "a USER account."
                );
            }

            event.setAction(
                    "LOGIN_DENIED"
            );

            event.setFailedAttempts(
                    attempts
            );

            event.setHttpStatus(401);

            securityEventService
                    .recordEvent(event);


            checkForBruteForce(
                    ipAddress,
                    username,
                    actualRole,
                    requestedRole,
                    attempts
            );


            model.addAttribute(
                    "error",
                    "Login denied. Check your credentials and selected role."
            );

            return "login";
        }


        /*
         * Password is correct now.
         *
         * Check whether the person is trying
         * to authenticate using a role they
         * do NOT actually own.
         *
         * Example:
         *
         * user + demo123 + ADMIN
         */

        if (!actualRole.equals(
                requestedRole)) {

            failedAttempts.remove(
                    attemptKey
            );

            SecurityEvent event =
                    createBaseEvent(
                            ipAddress,
                            username
                    );

            event.setActualRole(
                    actualRole
            );

            event.setRequestedRole(
                    requestedRole
            );

            event.setEventType(
                    "ROLE_MISMATCH"
            );

            event.setRiskLevel(
                    "HIGH"
            );

            event.setExplanation(
                    actualRole
                    + " account attempted to authenticate "
                    + "using the "
                    + requestedRole
                    + " role."
            );

            event.setAction(
                    "LOGIN_DENIED"
            );

            event.setHttpStatus(403);

            securityEventService
                    .recordEvent(event);


            model.addAttribute(
                    "error",
                    "Login denied. The selected role is not authorized for this account."
            );

            return "login";
        }


        /*
         * ========================================
         * SUCCESSFUL LOGIN
         * ========================================
         */

        failedAttempts.remove(
                attemptKey
        );

        /*
         * Remove any previous session.
         */
        HttpSession previousSession =
                request.getSession(false);

        if (previousSession != null) {
            previousSession.invalidate();
        }


        HttpSession session =
                request.getSession(true);

        session.setAttribute(
                "username",
                username
        );

        session.setAttribute(
                "role",
                actualRole
        );


        if ("ADMIN".equals(
                actualRole)) {

            return "redirect:/admin/dashboard";
        }

        return "redirect:/profile";
    }


    /*
     * ========================================
     * USER PROFILE
     * ========================================
     */

    @GetMapping("/profile")
    public String profile(
            HttpServletRequest request,
            Model model) {

        HttpSession session =
                request.getSession(false);

        if (session == null) {
            return "redirect:/";
        }

        String username =
                String.valueOf(
                        session.getAttribute(
                                "username"
                        )
                );

        String role =
                String.valueOf(
                        session.getAttribute(
                                "role"
                        )
                );


        if (!"USER".equals(role)) {

            return "redirect:/admin/dashboard";
        }


        model.addAttribute(
                "username",
                username
        );

        model.addAttribute(
                "role",
                role
        );

        return "profile";
    }


    /*
     * ========================================
     * ADMIN DASHBOARD
     * ========================================
     *
     * ApiMisuseFilter also protects /admin/**
     */

    @GetMapping("/admin/dashboard")
    public String adminDashboard(
            HttpServletRequest request,
            Model model) {

        HttpSession session =
                request.getSession(false);

        if (session == null) {
            return "redirect:/";
        }

        model.addAttribute(
                "username",
                session.getAttribute(
                        "username"
                )
        );

        model.addAttribute(
                "role",
                session.getAttribute(
                        "role"
                )
        );

        return "admin-dashboard";
    }


    /*
     * ========================================
     * LOGOUT
     * ========================================
     */

    @PostMapping("/logout")
    public String logout(
            HttpServletRequest request) {

        HttpSession session =
                request.getSession(false);

        if (session != null) {

            session.invalidate();
        }

        return "redirect:/";
    }


    /*
     * ========================================
     * DEMO ACCOUNT ROLE LOOKUP
     * ========================================
     */

    private String findActualRole(
            String username) {

        if ("user".equalsIgnoreCase(
                username)) {

            return "USER";
        }

        if ("admin".equalsIgnoreCase(
                username)) {

            return "ADMIN";
        }

        return null;
    }


    /*
     * ========================================
     * PASSWORD CHECK
     * ========================================
     */

    private boolean isPasswordCorrect(
            String username,
            String password) {

        if ("user".equalsIgnoreCase(
                username)) {

            return "demo123".equals(
                    password
            );
        }

        if ("admin".equalsIgnoreCase(
                username)) {

            return "admin123".equals(
                    password
            );
        }

        return false;
    }


    /*
     * ========================================
     * FAILED ATTEMPT COUNTER
     * ========================================
     */

    private int incrementFailedAttempts(
            String key) {

        return failedAttempts.merge(
                key,
                1,
                Integer::sum
        );
    }


    /*
     * ========================================
     * BRUTE FORCE DETECTION
     * ========================================
     */

    private void checkForBruteForce(
            String ipAddress,
            String username,
            String actualRole,
            String requestedRole,
            int attempts) {

        /*
         * Trigger once when threshold
         * is reached.
         */

        if (attempts != 5) {
            return;
        }


        SecurityEvent event =
                createBaseEvent(
                        ipAddress,
                        username
                );

        event.setActualRole(
                actualRole
        );

        event.setRequestedRole(
                requestedRole
        );

        event.setEventType(
                "BRUTE_FORCE"
        );

        event.setFailedAttempts(
                attempts
        );

        event.setAction(
                "FLAGGED"
        );

        event.setHttpStatus(401);


        if ("ADMIN".equals(
                actualRole)) {

            event.setRiskLevel(
                    "CRITICAL"
            );

            event.setExplanation(
                    "Possible brute-force attack detected: "
                    + "5 consecutive authentication failures "
                    + "targeted a privileged ADMIN account "
                    + "from the same client IP."
            );

        } else {

            event.setRiskLevel(
                    "HIGH"
            );

            event.setExplanation(
                    "Possible brute-force attack detected: "
                    + "5 consecutive failed authentication "
                    + "attempts originated from the same "
                    + "client IP."
            );
        }


        securityEventService
                .recordEvent(event);
    }


    /*
     * ========================================
     * COMMON SECURITY EVENT DATA
     * ========================================
     */

    private SecurityEvent createBaseEvent(
            String ipAddress,
            String username) {

        SecurityEvent event =
                new SecurityEvent();

        event.setIpAddress(
                ipAddress
        );

        event.setUsername(
                username
        );

        event.setEndpoint(
                "/login"
        );

        event.setMethod(
                "POST"
        );

        return event;
    }
}