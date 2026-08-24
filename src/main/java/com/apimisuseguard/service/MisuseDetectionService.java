package com.apimisuseguard.service;

import com.apimisuseguard.model.ApiRequest;
import org.springframework.stereotype.Service;

@Service
public class MisuseDetectionService {

    public void analyzeRequest(ApiRequest request) {

        // Rule 1: Suspicious / SQL injection-like payload
        if (request.getPayload() != null) {

            String payload = request.getPayload().toLowerCase();

            if (payload.contains("union select")
                    || payload.contains("' or '1'='1")
                    || payload.contains("' or 1=1")) {

                request.setRiskLevel("CRITICAL");
                request.setDetectionReason("Suspicious Payload");
                return;
            }
        }

        // Rule 2: Unauthorized admin endpoint access
        if (request.getEndpoint() != null
                && request.getEndpoint().startsWith("/admin")
                && !"ADMIN".equalsIgnoreCase(request.getRole())) {

            request.setRiskLevel("CRITICAL");
            request.setDetectionReason("Unauthorized Access");
            return;
        }

        // Rule 3: Repeated failed login attempts
        if (request.getEndpoint() != null
                && request.getEndpoint().equalsIgnoreCase("/api/login")
                && request.getFailedAttempts() > 5) {

            request.setRiskLevel("HIGH");
            request.setDetectionReason("Brute Force");
            return;
        }

        // Rule 4: Too many requests in one minute
        if (request.getRequestsPerMinute() > 30) {

            request.setRiskLevel("HIGH");
            request.setDetectionReason("Rate Misuse");
            return;
        }

        // No suspicious activity found
        request.setRiskLevel("LOW");
        request.setDetectionReason("Normal Request");
    }
}