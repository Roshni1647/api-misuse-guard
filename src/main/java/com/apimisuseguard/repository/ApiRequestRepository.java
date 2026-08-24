package com.apimisuseguard.repository;

import com.apimisuseguard.model.ApiRequest;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiRequestRepository extends JpaRepository<ApiRequest, Long> {
}