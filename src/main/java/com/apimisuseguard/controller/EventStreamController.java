package com.apimisuseguard.controller;

import com.apimisuseguard.service.SecurityEventStreamService;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
public class EventStreamController {

    private final SecurityEventStreamService streamService;

    public EventStreamController(
            SecurityEventStreamService streamService) {

        this.streamService = streamService;
    }

    @GetMapping(
            value = "/events/stream",
            produces = MediaType.TEXT_EVENT_STREAM_VALUE
    )
    public SseEmitter streamEvents() {

        return streamService.subscribe();
    }
}