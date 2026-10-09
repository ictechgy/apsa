# 통합 코드의 출처

원래 Quaygate 0.9.4의 `quaygate/` 정적 파서·린트 및 기존 테스트는 원본 MIT 고지(`LICENSE`)를 보존합니다. Mobile Audit 1.0.0의 `src/mobile_audit`, 테스트·benchmark·운영 자료를 통합했습니다. 전체 통합 제품에 새로운 공개 라이선스를 부여하지 않았습니다. 이 두 내부 엔진은 외부 패키지나 별도 실행 파일을 요구하지 않습니다.

# Third-party notices

APSA 1.2.0 adds the runtime dependency `tree-sitter-objc==3.0.2`. Its row below
was added from that version's installed distribution metadata (`License: MIT`
with a bundled `LICENSE` file); the other rows come from the earlier generated
table. Release validation regenerates notices and copies declared license files
from the actual installed distributions into the release bundle; this checkout
does not contain those copied files.

이 목록은 잠긴 Python 런타임 의존성의 실제 설치 메타데이터와 배포본에 포함된 라이선스 파일에서 생성했습니다.
라이선스 이름, 표현식, 저작권을 추측하거나 자체 제품의 라이선스를 지정하지 않습니다.
`dependency-licenses.json`에 원래 선언을 보존하며 `licenses/`에 발견한 원문 파일을 그대로 복사합니다.
파일 미포함 또는 선언 누락은 별도 표시합니다. 이 자료는 라이선스 의무의 법률적 판단을 대신하지 않습니다.

| 의존성 | 버전 | 메타데이터 선언 | 수집 상태 |
| --- | --- | --- | --- |
| alembic | 1.20.0 | MIT | files-copied |
| androguard | 4.1.4 | Apache Licence, Version 2.0 | files-copied |
| annotated-types | 0.8.0 | MIT | files-copied |
| anyio | 4.15.1 | MIT | files-copied |
| apkInspector | 1.3.7 | Apache-2.0 | files-copied |
| asn1crypto | 1.5.1 | MIT | files-copied |
| asttokens | 3.0.2 | Apache 2.0 | files-copied |
| attrs | 26.1.0 | MIT | files-copied |
| beautifulsoup4 | 4.15.0 | MIT License | files-copied |
| certifi | 2026.7.22 | MPL-2.0 | files-copied |
| cffi | 2.1.1 | MIT-0 | files-copied |
| click | 8.5.0 | BSD-3-Clause | files-copied |
| colorama | 0.4.6 | License :: OSI Approved :: BSD License | files-copied |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | files-copied |
| cvss | 3.6 | LGPLv3+ | files-copied |
| dataset | 2.0.0 | Copyright (c) 2013, Open Knowledge Foundation, Friedrich Lindenberg,   Gregor Aisch  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated docume (원문은 JSON 참조) | files-copied |
| defusedxml | 0.7.1 | PSFL | files-copied |
| executing | 2.2.1 | MIT | files-copied |
| h11 | 0.16.0 | MIT | files-copied |
| httpcore | 1.0.9 | BSD-3-Clause | files-copied |
| httpx | 0.28.1 | BSD-3-Clause | files-copied |
| httpx-sse | 0.4.3 | MIT | files-copied |
| idna | 3.20 | BSD-3-Clause | files-copied |
| ipython | 9.17.1 | BSD-3-Clause | files-copied |
| ipython_pygments_lexers | 1.1.1 | License :: OSI Approved :: BSD License | files-copied |
| jedi | 0.20.0 | MIT | files-copied |
| jsonschema | 4.26.0 | MIT | files-copied |
| jsonschema-specifications | 2025.9.1 | MIT | files-copied |
| linkify-it-py | 2.2.0 | MIT | files-copied |
| loguru | 0.7.3 | License :: OSI Approved :: MIT License | metadata-only |
| lxml | 6.1.3 | BSD-3-Clause | files-copied |
| Mako | 1.4.3 | MIT | files-copied |
| markdown-it-py | 4.2.0 | License :: OSI Approved :: MIT License | files-copied |
| MarkupSafe | 3.0.4 | BSD-3-Clause | files-copied |
| matplotlib-inline | 0.2.2 | BSD-3-Clause | files-copied |
| mcp | 1.30.0 | MIT | files-copied |
| mdit-py-plugins | 0.6.1 | License :: OSI Approved :: MIT License | files-copied |
| mdurl | 0.1.2 | License :: OSI Approved :: MIT License | files-copied |
| mutf8 | 1.1.0 | MIT | files-copied |
| networkx | 3.7 | BSD-3-Clause | files-copied |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | files-copied |
| parso | 0.8.7 | MIT | files-copied |
| pexpect | 4.9.0 | ISC license | files-copied |
| platformdirs | 4.12.3 | MIT | files-copied |
| prompt_toolkit | 3.0.53 | License :: OSI Approved :: BSD License | files-copied |
| psutil | 7.2.2 | BSD-3-Clause | files-copied |
| ptyprocess | 0.7.0 | UNKNOWN | files-copied |
| pure_eval | 0.2.4 | MIT | files-copied |
| pycparser | 3.0 | BSD-3-Clause | files-copied |
| pydantic | 2.13.5 | MIT | files-copied |
| pydantic_core | 2.46.5 | MIT | files-copied |
| pydantic-settings | 2.15.0 | MIT | files-copied |
| pydot | 4.0.1 | MIT | files-copied |
| Pygments | 2.21.0 | BSD-2-Clause | files-copied |
| PyJWT | 2.15.1 | MIT | files-copied |
| pyparsing | 3.3.3 | MIT | files-copied |
| python-dotenv | 1.2.4 | BSD-3-Clause | files-copied |
| python-multipart | 0.0.32 | Apache-2.0 | files-copied |
| PyYAML | 6.0.3 | MIT | files-copied |
| referencing | 0.37.0 | MIT | files-copied |
| rich | 14.3.4 | MIT | files-copied |
| rpds-py | 2026.6.3 | MIT | files-copied |
| soupsieve | 2.10 | MIT | files-copied |
| SQLAlchemy | 2.1.3 | MIT | files-copied |
| sse-starlette | 3.5.0 | BSD-3-Clause | files-copied |
| stack-data | 0.6.3 | MIT | files-copied |
| starlette | 1.7.0 | BSD-3-Clause | files-copied |
| textual | 8.2.8 | MIT | files-copied |
| traitlets | 5.16.1 | BSD 3-Clause License  - Copyright (c) 2001-, IPython Development Team  All rights reserved.  Redistribution and use in source and binary forms, with or without modification, are permitted provided tha (원문은 JSON 참조) | files-copied |
| tree-sitter | 0.25.2 | License :: OSI Approved :: MIT License | files-copied |
| tree-sitter-java | 0.23.5 | MIT | files-copied |
| tree-sitter-json | 0.24.8 | MIT | files-copied |
| tree-sitter-kotlin | 1.1.0 | MIT | files-copied |
| tree-sitter-objc | 3.0.2 | MIT | files-copied |
| tree-sitter-swift | 0.7.4 | MIT | files-copied |
| typing_extensions | 4.16.0 | PSF-2.0 | files-copied |
| typing-inspection | 0.4.4 | MIT | files-copied |
| uvicorn | 0.54.0 | BSD-3-Clause | files-copied |
| wcwidth | 0.9.1 | License :: OSI Approved :: MIT License | files-copied |
