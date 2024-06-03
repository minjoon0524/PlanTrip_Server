package plan.trip.member.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import plan.trip.member.Service.MemberService;
import plan.trip.member.dto.LoginRequestDto;
import plan.trip.member.dto.MemberFormDto;
import plan.trip.member.entity.Member;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:3000")
public class MemberController {
    private final MemberService memberService;
    private final PasswordEncoder passwordEncoder;

    // 회원가입을 위한 매핑
    @PostMapping("/member/new")
    public ResponseEntity<?> saveMember(@Valid @RequestBody MemberFormDto memberFormDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            // 입력값 검증 결과 에러가 있을 경우
            return ResponseEntity.badRequest().body(bindingResult.getAllErrors());
        }

        try {
            // 회원가입 정보를 Member 객체로 변환
            Member member = Member.createMember(memberFormDto, passwordEncoder);
            // 회원가입 정보를 DB에 저장
            memberService.saveMember(member);
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }

        return ResponseEntity.ok("Success");
    }

    // 로그인을 위한 매핑
    @PostMapping("/member/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDto loginRequestDto) {
        System.out.println(loginRequestDto);
        try {
            // 로그인 요청을 서비스 계층으로 전달하여 로그인 처리
            Member member = memberService.login(loginRequestDto);
            return ResponseEntity.ok("로그인 성공"); // 로그인 성공 시 성공 메시지 반환
        } catch (IllegalArgumentException e) {
            // 로그인 실패 시 예외 처리
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("이메일 또는 비밀번호가 잘못되었습니다."); // 로그인 실패 시 실패 메시지 반환
        }
    }


    //로그아웃 기능 구현

    //
    @GetMapping("/member/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return ResponseEntity.ok().build();
    }

    //로그인 체크 매핑
    @GetMapping("/member/checkLoginStatus")
    public ResponseEntity<Map<String, Boolean>> checkLoginStatus(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isLoggedIn = auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken);
        Map<String, Boolean> response = new HashMap<>();
        response.put("isLoggedIn", isLoggedIn);
        return ResponseEntity.ok(response);
    }
}