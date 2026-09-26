# SBOM Parser

AGENTS.md와 ROADMAP.md의 Phase 2는 SBOM Parser이며 초기 지원은 CycloneDX JSON이다.
정규화는 Phase 3, 검증용 SBOM Diff는 Phase 9, 비교 집계는 Phase 10에서 담당한다.
생성 Wrapper와 DB 저장은 ROADMAP.md의 공통 지원 작업으로 관리한다.

## 사용

Python 3.10 이상, 표준 라이브러리만 사용한다. 저장소 루트에서 실행한다.

```python
from core.sbom.parser import parse_sbom_file

sbom = parse_sbom_file('tests/fixtures/cyclonedx.json')
for component in sbom.components:
    print(component.name, component.version, component.purl)
```

문자열 입력은 `parse_sbom(content)`를 사용한다.

## 계약과 한계

- CycloneDX JSON 1.4, 1.5, 1.6을 지원한다. XML과 다른 버전/형식은
  `UnsupportedSBOMFormat`으로 거부한다.
- 이름, 유형, 버전, PURL, bom-ref, group, supplier, hashes, licenses를 추출한다.
  supplier와 라이선스 상세는 원문 구조를 보존한다.
- 이름·유형은 필수다. 없는 선택 문자열은 `None`, 없는 해시·라이선스는 빈 tuple이다.
  명시적인 null이나 잘못된 타입은 오류이며 버전/PURL을 추측하거나 정규화하지 않는다.
- `metadata.component`는 `metadata_component`로 별도 반환한다. 그 하위 및 최상위
  `components`는 입력 순서를 유지하며 깊이 우선으로 평탄화한다.
  중첩 관계는 `parent_ref`에 기록하며 dependency 관계로 추정하지 않는다.
- 같은 이름/버전의 별도 구성요소는 보존한다. 중복 component bom-ref는 오류다.
  bom-ref가 없는 구성요소는 식별자를 생성하거나 자동 병합하지 않는다.
- `dependencies`는 ref → dependsOn tuple이다. 필드 누락은 `None`, 명시적인 빈 목록은
  `{}`다. 참조 해석은 수행하지 않으며 외부/서비스/미해결 참조도 그대로 보존한다.
- 잘못된 JSON, 중복 JSON 키, 추출 필드 오류, 파일/인코딩 오류는
  `SBOMParsingError`로 전달한다. 형식 예외는 이 클래스의 하위 클래스다.
- 전체 JSON Schema 검증, PURL 문법 검증, 해시 검증, 의존성 완전성 판정은 하지 않는다.
  파싱 성공은 취약점 유무나 Evidence의 진위를 검증한 결과가 아니다.
- dataclass의 필드 재할당은 금지되지만 내부 dict는 변경 가능하므로 호출자가 원본 결과를
  수정하지 않도록 한다. 파일 크기 제한은 향후 업로드 계층에서 적용해야 한다.

추출 구조 참고: [CycloneDX 1.6 공식 스키마](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json).

## 검증

```powershell
python -m unittest discover -s tests/unit -v
```

`tests/fixtures/cyclonedx.json`은 파서 테스트용 합성 자료다. 구성요소·버전·해시는
실제 설치 상태나 스캐너 결과가 아니며 취약점 매칭 근거로 사용하지 않는다.
