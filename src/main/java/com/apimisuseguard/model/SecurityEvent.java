package com.apimisuseguard.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;

import java.time.LocalDateTime;

@Entity
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDateTime timestamp;

    private String ipAddress;

    private String username;

    private String endpoint;

    private String method;

    /*
     * Role actually owned by the account/session.
     *
     * Examples:
     * USER
     * ADMIN
     * GUEST
     */
    private String actualRole;

    /*
     * Role selected/requested on login.
     *
     * Example:
     * USER account selects ADMIN.
     */
    private String requestedRole;

    /*
     * Examples:
     *
     * FAILED_LOGIN
     * ROLE_MISMATCH
     * BRUTE_FORCE
     * UNAUTHORIZED_ACCESS
     * RATE_MISUSE
     * SUSPICIOUS_INPUT
     */
    private String eventType;

    /*
     * LOW
     * MEDIUM
     * HIGH
     * CRITICAL
     */
    private String riskLevel;

    /*
     * Human-readable reason explaining
     * why the activity was suspicious.
     */
    private String explanation;

    /*
     * Examples:
     *
     * LOGIN_DENIED
     * BLOCKED
     * FLAGGED
     */
    private String action;

    private int failedAttempts;

    private int requestsPerMinute;

    private int httpStatus;

    public SecurityEvent() {
    }

    @PrePersist
    public void setTimestampBeforeSaving() {

        if (timestamp == null) {
            timestamp = LocalDateTime.now();
        }
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getActualRole() {
        return actualRole;
    }

    public void setActualRole(String actualRole) {
        this.actualRole = actualRole;
    }

    public String getRequestedRole() {
        return requestedRole;
    }

    public void setRequestedRole(String requestedRole) {
        this.requestedRole = requestedRole;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public int getRequestsPerMinute() {
        return requestsPerMinute;
    }

    public void setRequestsPerMinute(int requestsPerMinute) {
        this.requestsPerMinute = requestsPerMinute;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(int httpStatus) {
        this.httpStatus = httpStatus;
    }
}