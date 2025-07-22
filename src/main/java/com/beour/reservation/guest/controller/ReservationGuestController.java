package com.beour.reservation.guest.controller;

import com.beour.global.response.ApiResponse;
import com.beour.reservation.guest.dto.CheckAvailableTimesRequestDto;
import com.beour.reservation.guest.dto.ReservationCreateRequest;
import com.beour.reservation.guest.dto.ReservationListResponseDto;
import com.beour.reservation.guest.dto.ReservationResponseDto;
import com.beour.reservation.guest.dto.SpaceAvailableTimeResponseDto;
import com.beour.reservation.guest.service.CheckAvailableTimeService;
import com.beour.reservation.guest.service.ReservationGuestService;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class ReservationGuestController {

    private final ReservationGuestService reservationGuestService;
    private final CheckAvailableTimeService checkAvailableTimeService;

    @PostMapping("/api/spaces/{spaceId}/reservations")
    public ApiResponse<ReservationResponseDto> createReservation(@PathVariable(value = "spaceId")Long spaceId, @Valid @RequestBody ReservationCreateRequest requestDto){
        return ApiResponse.ok(reservationGuestService.createReservation(spaceId, requestDto));
    }

    @PostMapping("/api/spaces/reserve/available-times")
    public ApiResponse<SpaceAvailableTimeResponseDto> checkAvailableTimes(@Valid @RequestBody CheckAvailableTimesRequestDto requestDto){
        return ApiResponse.ok(checkAvailableTimeService.findAvailableTime(requestDto));
    }

    @GetMapping("/api/reservation")
    public ApiResponse<List<ReservationListResponseDto>> checkReservationList(){
        return ApiResponse.ok(reservationGuestService.findReservationList());
    }

    @GetMapping("/api/reservation/past")
    public ApiResponse<List<ReservationListResponseDto>> checkPastReservationList(){
        return ApiResponse.ok(reservationGuestService.findPastReservationList());
    }

    @DeleteMapping("/api/reservation/cancel")
    public ApiResponse<String> cancelReservation(@RequestParam(value = "reservationId") Long reservationId){
        reservationGuestService.cancelReservation(reservationId);
        return ApiResponse.ok("예약이 성공적으로 취소되었습니다.");
    }
}
