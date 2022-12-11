package com.codestates.member.dto;

import com.codestates.member.entity.Member;
import com.codestates.stamp.Stamp;
import com.codestates.validator.NotSpace;
import lombok.AllArgsConstructor;
import lombok.Getter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

public class MemberDto {

    @AllArgsConstructor
    @Getter
    public static class Response {
        private long memberId;
        private String email;
        private Stamp stamp;
        public int getStamp() {
            return stamp.getStampCount();
        }
    }
}
