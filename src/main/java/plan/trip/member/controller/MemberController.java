package plan.trip.member.controller;

import jakarta.servlet.http.Cookie;
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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import plan.trip.member.Service.MemberService;
import plan.trip.member.dto.LoginRequestDto;
import plan.trip.member.dto.MemberFormDto;
import plan.trip.member.entity.Member;

import java.security.Principal;
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
//    @PostMapping("/member/login")
//    public ResponseEntity<?> login(@RequestBody LoginRequestDto loginRequestDto) {
//        System.out.println(loginRequestDto);
//        try {
//            // 로그인 요청을 서비스 계층으로 전달하여 로그인 처리
//            Member member = memberService.login(loginRequestDto);
//            System.out.println(member);
//            return ResponseEntity.ok("로그인 성공"); // 로그인 성공 시 성공 메시지 반환
//        } catch (IllegalArgumentException e) {
//            // 로그인 실패 시 예외 처리
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("이메일 또는 비밀번호가 잘못되었습니다."); // 로그인 실패 시 실패 메시지 반환
//        }
//
//
//    }

    // 로그인 요청 처리
    @PostMapping("/member/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDto loginRequestDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            // 요청 바디에 문제가 있을 경우, 예: 필드 검증 실패
            return ResponseEntity.badRequest().body("올바르지 않은 요청입니다.");
        }

        try {
            // 로그인 시도하는 사용자의 이메일로 UserDetails 객체 얻기
            UserDetails userDetails = memberService.loadUserByUsername(loginRequestDto.getEmail());

            // 비밀번호 검증 로직
            if(passwordEncoder.matches(loginRequestDto.getPassword(), userDetails.getPassword())) {
                // 로그인 성공 처리 (예: JWT 토큰 생성 및 반환)
                return ResponseEntity.ok().body("로그인 성공"+userDetails);
            } else {
                // 비밀번호 불일치 시
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("비밀번호가 틀렸습니다.");
            }
        } catch (UsernameNotFoundException e) {
            // 사용자를 찾을 수 없는 경우
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("회원가입이 필요합니다.");
        }
    }


    //로그아웃 기능 구현

    //
    @PostMapping("/member/logout") // POST 요청으로 변경
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }

        // 클라이언트에게 쿠키를 삭제하도록 설정
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
        }

        return ResponseEntity.ok().build();
    }


    //로그인 체크 매핑
    @GetMapping("/member/checkLoginStatus")
    public ResponseEntity<Map<String, Boolean>> checkLoginStatus(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Authentication: {}", auth);  // 로그 추가
        boolean isLoggedIn = auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken);
        Map<String, Boolean> response = new HashMap<>();
        response.put("isLoggedIn", isLoggedIn);
        log.info("isLoggedIn: {}", isLoggedIn);  // 로그 추가
        return ResponseEntity.ok(response);
    }

//    @GetMapping("/member/details")
//    @ResponseBody
//    public ResponseEntity<?> getMemberDetails(HttpServletRequest request, Principal principal) {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
//            String email = auth.getName();
//            MemberFormDto memberDetails = memberService.getSearchByMember(email);
//            return ResponseEntity.ok(principal.getName());
//        }
//        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("로그인이 필요합니다.");
//    }


    @GetMapping("/member/details")
    @ResponseBody
    public ResponseEntity<?> getMemberDetails(HttpServletRequest request, Principal principal) {
        return ResponseEntity.ok(principal.getName());
    }
}




