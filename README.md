# Web Guardner Project Convention

본 프로젝트는 Python(Flask) + Machine Learning / Deep Learning + Streamlit 기반으로 개발되며, 협업의 일관성과 유지보수성을 위해 아래 컨벤션을 따른다.

## Folder Convention

### Directory

디렉터리명은 소문자 `snake_case`를 사용한다.
여러 단어는 `_`로 구분한다.

```text
web_guardner/
├── app/                    # Flask 취약 서버
├── pipeline/               # 로그 수집 및 전처리
├── models/                 # ML/DL 모델
│   ├── filtering/          # 1·2차 AI 필터링
│   │   ├── isolation_forest.py
│   │   └── keras_classifier.py
│   ├── scoring/            # 위험도 계산
│   │   └── risk_scoring.py
│   └── saved/              # 학습된 모델 저장
│       ├── isolation_forest.pkl
│       └── keras_model.keras
├── ai/                     # OpenAI API 및 AI 보고서 생성
├── dashboard/              # Streamlit Dashboard
├── data/
│   ├── raw/
│   ├── processed/
│   └── output/
├── docs/
├── tests/
├── requirements.txt
└── README.md
```

### Python File

Python 파일명 역시 `snake_case`를 사용한다.

```text
train_model.py
predict_attack.py
log_parser.py
openai_report.py
```

### Notebook

Notebook은 실행 순서를 쉽게 확인할 수 있도록 번호를 붙인다.

```text
01_data_analysis.ipynb
02_preprocessing.ipynb
03_model_training.ipynb
04_model_evaluation.ipynb
```

## Code Convention

Python 공식 스타일 가이드인 PEP 8을 따른다.

### Variable

변수명은 `snake_case`를 사용한다.

```text
user_input
model_path
attack_count
```

### Function

함수명은 `snake_case`를 사용한다.

```python
def train_model():
    ...

def predict_attack():
    ...
```

### Class

클래스명은 `PascalCase`를 사용한다.

```python
class LogClassifier:
    ...

class OpenAIReporter:
    ...
```

### Constant

상수 및 환경 변수는 `UPPER_SNAKE_CASE`를 사용한다.

```text
OPENAI_API_KEY
MODEL_PATH
MAX_LENGTH
```

`.env`

```text
OPENAI_API_KEY=
FLASK_HOST=
MODEL_PATH=
```

### Import Order

Import는 아래 순서를 따른다.

1. Python Standard Library
2. Third-party Library
3. Project Module

```python
import os
import json

import pandas as pd
from sklearn.model_selection import train_test_split

from utils.parser import parse_log
```

### Comment

주석은 무엇을 하는지보다 왜 하는지를 설명하는 것을 권장한다.

Good:

```python
# SQL Injection 패턴 제거 후 모델 입력 데이터 생성
```

Bad:

```python
# 변수 선언
```

## Machine Learning Convention

모델 학습과 추론 로직은 분리하여 관리한다.

```text
train.py
predict.py
```

전처리 로직은 별도 파일로 관리한다.

```text
preprocess.py
```

모델 구현은 모델별 파일로 관리한다.

```text
models/
├── random_forest.py
├── xgboost_model.py
└── isolation_forest.py
```

학습 완료된 모델은 별도 디렉터리에 저장한다.

```text
saved_models/
├── random_forest.pkl
├── scaler.pkl
└── tokenizer.pkl
```

## Git Branch Strategy

본 프로젝트는 Git Flow를 기반으로 한 경량 브랜치 전략을 사용한다.

### Branch Structure

```text
main
│
└── develop
    ├── feat/log-parser
    ├── feat/ml-model
    ├── feat/dashboard
    ├── feat/openai-report
    └── hotfix/login-error
```

### Branch Description

| Branch | Description |
| --- | --- |
| `main` | 최종 배포 및 발표 버전 |
| `develop` | 개발 브랜치 |
| `feat/*` | 기능 개발 브랜치 |
| `hotfix/*` | 배포 이후 긴급 버그 수정 |

Release 브랜치는 사용하지 않습니다.

본 프로젝트는 3~4일 단기 프로젝트로 별도의 QA 및 릴리즈 기간이 없기 때문에 release 브랜치는 운영하지 않습니다.

### Workflow

1. 기능 개발

`develop` 브랜치에서 새로운 `feat` 브랜치를 생성한다.

```bash
git checkout develop
git pull origin develop

git checkout -b feat/ml-model
```

개발 완료 후 Pull Request를 생성하여 `develop` 브랜치로 Merge한다.

2. 최종 배포

모든 기능 개발이 완료되면 `develop` 브랜치를 `main` 브랜치로 Merge한다.

```text
feat/*
       │
       ▼
     develop
       │
       ▼
     main
```

3. Hotfix

배포 이후 긴급 수정이 필요한 경우 `main` 브랜치에서 `hotfix` 브랜치를 생성한다.

```bash
git checkout main
git pull origin main

git checkout -b hotfix/login-error
```

수정 완료 후 `main`과 `develop` 모두에 Merge한다.

```text
main
 └── hotfix/*
       │
       ├──► main
       └──► develop
```

## Commit Convention

커밋 메시지는 아래 규칙을 따른다.

```text
<type>: <message>
```

Merge commit을 포함한 모든 신규 커밋에 같은 형식을 적용한다. 저장소의 `commit-msg` Hook은 제목 첫 줄이 이 형식과 허용된 type을 사용하는지 검증한다. 저장소를 처음 받은 뒤 다음 명령으로 Hook을 활성화한다.

```bash
git config core.hooksPath .githooks
```

### Commit Type

| Type | Description |
| --- | --- |
| `feat` | 새로운 기능 추가 |
| `fix` | 버그 수정 |
| `hotfix` | 긴급 버그 수정 |
| `refactor` | 코드 리팩토링 |
| `style` | 코드 스타일 및 UI 수정 |
| `docs` | 문서 수정 |
| `test` | 테스트 코드 |
| `comment` | 주석 추가 및 수정 |
| `rename` | 파일 또는 폴더 이름 변경 |
| `remove` | 파일 삭제 |
| `chore` | 빌드, 환경설정 등 기타 작업 |

### Example

```text
feat: Flask 로그 수집 API 구현
feat: RandomForest 모델 학습 기능 추가
fix: SQL Injection 탐지 오류 수정
docs: README 작성
style: Streamlit UI 개선
refactor: 로그 파싱 로직 개선
test: 모델 성능 평가 코드 추가
rename: parser.py → log_parser.py
remove: 미사용 모델 삭제
hotfix: 로그인 오류 긴급 수정
```

## Collaboration Rules

- 기능 개발 전 Issue 생성을 권장한다.
- 기능 단위로 Commit을 작성한다.
- Merge 전 Pull Request를 생성한다.
- 공통 코드 수정 시 팀원과 사전에 공유한다.
- Merge Conflict 발생 시 임의로 해결하지 않고 팀원과 협의한다.
- 모르는 부분은 적극적으로 질문한다.
- 개선 아이디어는 자유롭게 제안한다.

## Git Ignore

다음과 같은 파일은 Git으로 관리하지 않는다.

```gitignore
# Environment
.env
.venv/

# Python
__pycache__/
*.py[cod]

# ML Model
*.pkl
*.joblib

# Dataset
**/data/raw/
**/data/output/

# Database
*.db

# Logs
*.log

# macOS
.DS_Store
```
