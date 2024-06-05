package plan.trip.member.Service;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import plan.trip.member.Repository.MemberRepository;
import plan.trip.member.dto.LoginRequestDto;
import plan.trip.member.dto.MemberFormDto;
import plan.trip.member.entity.Member;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberService implements UserDetailsService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    // Member를 저장하기 위한 로직
    public Member saveMember(Member member){
        validateDuplicationMember(member);
        member.setPassword(passwordEncoder.encode(member.getPassword())); // 비밀번호 암호화
        return memberRepository.save(member);
    }

    // Member 검증을 위한 비즈니스 로직
    private void validateDuplicationMember(Member member) {
        Optional<Member> findMember = memberRepository.findByEmail(member.getEmail());
        if(findMember.isPresent()){
            throw new IllegalStateException("이미 존재하는 회원입니다.");
        }
    }

    // 로그인 로직(HttpSession 사용)
    public Member login(LoginRequestDto loginRequestDto, HttpSession session) {
        Member member = memberRepository.findByEmail(loginRequestDto.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + loginRequestDto.getEmail()));

        if (!passwordEncoder.matches(loginRequestDto.getPassword(), member.getPassword())) {
            throw new IllegalArgumentException("이메일 또는 비밀번호가 잘못되었습니다.");
        }

        // 로그인 성공 시 세션에 사용자 정보 저장
        session.setAttribute("loggedInUser", member);
        return member;
    }

    // 로그아웃 로직
    public void logout(HttpSession session) {
        session.invalidate(); // 세션 무효화
    }

    // 이메일로 사용자 조회 로직
    public Member findByEmail(String email) {
        return memberRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
    }

    // 로그인한 member의 이름을 가져오는 로직
    public String getMemberNameByEmail(String email) {
        Member member = findByEmail(email);
        return member.getName();
    }

    // 사용자 조회를 위한 로직
    public MemberFormDto getSearchByMember(String email) {
        Member member = findByEmail(email);
        return MemberFormDto.searchByMember(member);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("해당 사용자가 없습니다: " + email));
        log.info("===========[로그인 사용자] : " + member);

        return User.builder()
                .username(member.getEmail())
                .password(member.getPassword())
                .roles(member.getRole().toString())
                .build();
    }
}
