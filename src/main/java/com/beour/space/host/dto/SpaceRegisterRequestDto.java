package com.beour.space.host.dto;

import com.beour.space.domain.enums.SpaceCategory;
import com.beour.space.domain.enums.UseCategory;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import java.util.List;

@Getter
public class SpaceRegisterRequestDto {
    // 1. Space
    @NotBlank(message = "공간명은 필수입니다.")
    private String name;

    @NotNull(message = "공간 유형은 필수입니다.")
    private SpaceCategory spaceCategory;

    @NotNull(message = "사용 용도는 필수입니다.")
    private UseCategory useCategory;

    @Min(1)
    private int maxCapacity;

    @NotBlank(message = "주소는 필수입니다.")
    private String address;

    @NotBlank(message = "상세 주소는 필수입니다.")
    private String detailAddress;

    @Min(1)
    private int pricePerHour;

    private String thumbnailUrl;

    // 2. Description
    @NotBlank(message = "공간 설명은 필수입니다.")
    private String description;

    private String priceGuide;
    private String facilityNotice;

    @NotBlank(message = "주의 사항은 필수입니다.")
    private String notice;

    private String locationDescription;

    @NotBlank(message = "환불 정책은 필수입니다.")
    private String refundPolicy;

    // 3. Tags
    private List<String> tags;

    // 4. SpaceImages
    private List<String> imageUrls;
}
