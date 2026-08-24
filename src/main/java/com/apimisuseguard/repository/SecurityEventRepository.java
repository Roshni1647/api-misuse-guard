package com.apimisuseguard.repository;

import com.apimisuseguard.model.SecurityEvent;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SecurityEventRepository
        extends JpaRepository<SecurityEvent, Long> {

    List<SecurityEvent> findAllByOrderByTimestampDesc();
}