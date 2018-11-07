package com.apap.tutorial8.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.apap.tutorial8.model.FlightModel;


@Repository
public interface FlightDb extends JpaRepository<FlightModel, Long> {
    void deleteByFlightNumber(String flightNumber);

    Optional<FlightModel> findByFlightNumber(String flightNumber);
}