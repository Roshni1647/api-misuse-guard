package com.apimisuseguard.service;

import com.apimisuseguard.model.ApiRequest;
import com.apimisuseguard.model.SecurityEvent;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Service
public class SecurityEventStreamService {

    private final List<SseEmitter> emitters =
            new CopyOnWriteArrayList<>();

    /*
     * Browser calls /events/stream.
     *
     * We keep that connection open so that
     * Spring Boot can push security events
     * immediately to the dashboard.
     */
    public SseEmitter subscribe() {

        SseEmitter emitter =
                new SseEmitter(0L);

        emitters.add(emitter);

        emitter.onCompletion(
                () -> emitters.remove(emitter)
        );

        emitter.onTimeout(
                () -> emitters.remove(emitter)
        );

        emitter.onError(
                error -> emitters.remove(emitter)
        );

        try {

            emitter.send(
                    SseEmitter.event()
                            .name("connected")
                            .data(
                                    "Live security monitoring connected"
                            )
            );

        } catch (IOException e) {

            emitters.remove(emitter);
        }

        return emitter;
    }


    /*
     * NEW SYSTEM
     *
     * Sends SecurityEvent objects to the dashboard.
     */
    public void publish(
            SecurityEvent securityEvent) {

        sendEvent(
                "security-event",
                securityEvent
        );
    }


    /*
     * TEMPORARY LEGACY SUPPORT
     *
     * Keep this only while ApiMisuseFilter
     * still uses ApiRequest.
     *
     * We will remove this later.
     */
    public void publish(
            ApiRequest apiRequest) {

        sendEvent(
                "security-event",
                apiRequest
        );
    }


    /*
     * Common SSE sending method.
     */
    private void sendEvent(
            String eventName,
            Object data) {

        for (SseEmitter emitter : emitters) {

            try {

                emitter.send(
                        SseEmitter.event()
                                .name(eventName)
                                .data(
                                        data,
                                        MediaType.APPLICATION_JSON
                                )
                );

            } catch (IOException e) {

                emitters.remove(emitter);
            }
        }
    }
}