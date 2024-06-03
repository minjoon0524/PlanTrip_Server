package plan.trip.member.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import plan.trip.member.Repository.MemberRepository;
import plan.trip.member.dto.LoginRequestDto;
import plan.trip.member.entity.Member;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    //Member를 저장하기 위한 로직
    public Member saveMember(Member member){
        validateDuplicationMember(member);
        return memberRepository.save(member);
    }
    //Member검증을 위한 비지니스 로직
    private void validateDuplicationMember(Member member) {
        Optional<Member> findMember = memberRepository.findByEmail(member.getEmail());

        if(findMember.isPresent()){
            System.out.println(findMember.get().getName());
            throw new IllegalStateException("이미 존재하는 회원입니다.");
        }

    }
    //1. 사용자는 로그인 버튼을 누른다.
    //2. 사용자의 이메일과 비밀번호를 확인한다.(findByEmail,findByPassword과 frontEnd에서 전달한 login과password값 비교)
    //3. 이메일 또는 비밀번호가 틀릴 경우 에러 메시지를 전달한다.
    //4. 로그인 성공시 로그인 성공 메시지를 전달한다.
    public Member login(LoginRequestDto loginRequestDto) {
        // 사용자의 이메일로 회원을 조회
        Member member = memberRepository.findByEmail(loginRequestDto.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + loginRequestDto.getEmail()));

        // 사용자가 입력한 비밀번호와 회원의 비밀번호를 비교하여 일치하는지 확인
        if (!passwordEncoder.matches(loginRequestDto.getPassword(), member.getPassword())) {
            throw new IllegalArgumentException("이메일 또는 비밀번호가 잘못되었습니다.");
        }

        return member;
    }

    // member를 찾기위한 로직
    public Member findByEmail(String email) {
        return memberRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));}



}
