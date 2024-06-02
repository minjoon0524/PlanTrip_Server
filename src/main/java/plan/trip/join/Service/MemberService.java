package plan.trip.join.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import plan.trip.join.Repository.MemberRepository;
import plan.trip.join.entity.Member;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberService {

    private final MemberRepository memberRepository;
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


}
