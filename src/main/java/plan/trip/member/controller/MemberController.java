package plan.trip.member.controller;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import plan.trip.member.Service.MemberService;
import plan.trip.member.dto.LoginRequestDto;
import plan.trip.member.dto.MemberFormDto;
import plan.trip.member.entity.Member;

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



    // 로그인 요청 처리
    @PostMapping("/member/login")
    public ResponseEntity<String> login(@RequestBody LoginRequestDto loginRequestDto, HttpSession session) {
        memberService.login(loginRequestDto, session);
        return ResponseEntity.ok("로그인 성공");
    }


    //로그아웃 기능 구현
    @PostMapping("/member/logout") // POST 요청으로 변경
    public ResponseEntity<String> logout(HttpSession session) {
        memberService.logout(session);
        return ResponseEntity.ok("로그아웃 성공");
    }

    @GetMapping("/member/status")
    public ResponseEntity<String> loginStatus(HttpSession session) {
        Member member = (Member) session.getAttribute("loggedInUser");
        if (member != null) {
            return ResponseEntity.ok(member.getName());
        } else {
            return ResponseEntity.status(401).body("로그인되지 않음");
        }
    }

}




