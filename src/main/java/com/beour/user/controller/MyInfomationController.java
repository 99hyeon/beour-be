package com.beour.user.controller;

import com.beour.global.response.ApiResponse;
import com.beour.user.dto.ChangePasswordRequestDto;
import com.beour.user.dto.UpdateUserInfoRequestDto;
import com.beour.user.dto.UpdateUserInfoResponseDto;
import com.beour.user.dto.UserInformationDetailResponseDto;
import com.beour.user.dto.UserInformationSimpleResponseDto;
import com.beour.user.service.MyInformationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RequestMapping("/api/users")
@RestController
public class MyInfomationController {

    private final MyInformationService myInformationService;

    @GetMapping("/me")
    public ApiResponse<UserInformationSimpleResponseDto> readInformation(){
        return ApiResponse.ok(myInformationService.getUserInformationSimple());
    }

    @GetMapping("/me/detail")
    public ApiResponse<UserInformationDetailResponseDto> readDetailInformation(){
        return ApiResponse.ok(myInformationService.getUserInformationDetail());
    }

    @PatchMapping("/me/detail")
    public ApiResponse<UpdateUserInfoResponseDto> updateUserInformation(@Valid @RequestBody UpdateUserInfoRequestDto requestDto){
        return ApiResponse.ok(myInformationService.updateUserInfo(requestDto));
    }

    @PatchMapping("/me/password")
    public ApiResponse<String> updatePassword(@Valid @RequestBody ChangePasswordRequestDto requestDto){
        myInformationService.updatePassword(requestDto);

        return ApiResponse.ok("비밀번호 변경이 완료되었습니다.");
    }

    @DeleteMapping
    public ApiResponse<String> userWithdraw(){
        myInformationService.deleteUser();

        return ApiResponse.ok("회원 탈퇴가 완료되었습니다.");
    }
}
