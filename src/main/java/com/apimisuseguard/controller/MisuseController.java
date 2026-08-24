package com.apimisuseguard.controller;

import com.apimisuseguard.model.SecurityEvent;
import com.apimisuseguard.service.SecurityEventService;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MisuseController {

    private final SecurityEventService
            securityEventService;


    public MisuseController(
            SecurityEventService securityEventService) {

        this.securityEventService =
                securityEventService;
    }


    @GetMapping("/security-dashboard")
    public String securityDashboard(
            Model model) {

        List<SecurityEvent> events =
                securityEventService
                        .getAllEvents();


        long highThreats =
                events.stream()
                        .filter(
                                event ->
                                        "HIGH".equals(
                                                event.getRiskLevel()
                                        )
                        )
                        .count();


        long criticalThreats =
                events.stream()
                        .filter(
                                event ->
                                        "CRITICAL".equals(
                                                event.getRiskLevel()
                                        )
                        )
                        .count();


        model.addAttribute(
                "events",
                events
        );

        model.addAttribute(
                "totalThreats",
                events.size()
        );

        model.addAttribute(
                "highThreats",
                highThreats
        );

        model.addAttribute(
                "criticalThreats",
                criticalThreats
        );


        return "index";
    }
}