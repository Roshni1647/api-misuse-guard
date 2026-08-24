package com.apimisuseguard.service;

import com.apimisuseguard.model.SecurityEvent;
import com.apimisuseguard.repository.SecurityEventRepository;

import java.util.List;

import org.springframework.stereotype.Service;

@Service
public class SecurityEventService {

    private final SecurityEventRepository repository;

    private final SecurityEventStreamService streamService;


    public SecurityEventService(
            SecurityEventRepository repository,
            SecurityEventStreamService streamService) {

        this.repository = repository;
        this.streamService = streamService;
    }


    /*
     * =================================================
     * CENTRAL SECURITY EVENT METHOD
     * =================================================
     *
     * Every security event in the application
     * should eventually pass through here.
     *
     * ONE call performs BOTH:
     *
     * 1. Save event to H2
     * 2. Push event through SSE
     */
    public SecurityEvent recordEvent(
            SecurityEvent securityEvent) {

        SecurityEvent savedEvent =
                repository.save(securityEvent);

        streamService.publish(savedEvent);

        return savedEvent;
    }


    /*
     * Used by the security dashboard.
     *
     * Newest event appears first.
     */
    public List<SecurityEvent> getAllEvents() {

        return repository
                .findAllByOrderByTimestampDesc();
    }


    /*
     * Useful for dashboard statistics.
     */
    public long getTotalThreats() {

        return repository.count();
    }
}