# Malicious-Threat-Detection-System

#### 관련 자세한 내용은 [[2조]악성위협감지스템_결과보고서.pdf](https://github.com/chaeuny/Malicious-Threat-Detection-System/blob/1180a346b4be02037f64b433bff14d68c3bbc0c0/%5B2%EC%A1%B0%5D%EC%95%85%EC%84%B1%EC%9C%84%ED%98%91%EA%B0%90%EC%A7%80%EC%8A%A4%ED%85%9C_%EA%B2%B0%EA%B3%BC%EB%B3%B4%EA%B3%A0%EC%84%9C%20(1).pdf) 에 기록되어있습니다.

#### 2022년 1학기 IT 융합공학부 사이버보안 트랙 캡스톤 디자인에서 진행한 프로젝트 입니다.

#### 담당 업무
 - 사이버보안트랙 최원석 교수님의 지도를 받았습니다.
 - 조원
   - 이채은
     - 프로젝트 총괄 및 발표 자료, 보고서 작성 
     - Web base 개발
     - URL Scan 기능 구현
     - 광고 배너 차단 Chrome Extension 개발
     - 광고 배너 차단 알고리즘 구현
     - 기존 광고배너 기능 및 추가 기능 구현
        - Membrane 패턴 적용
        - ShawDOM bypass 적용
        - DangerZone Docker 환경 구축

   - 이은서
     - 발표 보고서 작성 
     - Django 환경 구축
     - File Scan 기능 구현
     - 광고 배너 Chrome Extension UI 개발
     - Dangerzone-Docker 서버 업로드 구현
     - Web UI

   - 송승민
     - Dangerzone-Docker 서버 업로드 및 다운로드 구현
   - 서아름
     - 발표 자료 제작 및 발표
     - 광고배너 기능 구현
     - Dangerzone-Docker 서버 업로드 구현
     - Web UI
       <br>
 

## 프로젝트 소개
 - 2022년 6월 첫째주 안랩 ASCE 분석팀의 보도자료에 따르면 가장 많이 발견된 악성코드인 'Form book'은 info stealer 악성코드로 전체의 33.7%을 차지한다. 다른 인포스틸러 악성코드들과 동일하게 스팸메일을 통해 유포되었다.
 - 스팸메일은 APT 공격의 주요 타겟으로 수일-수년에 걸친 지속적 공격이 가능하다. 
 - CDR(Content Disarm and Reconstruction)은 백신이나 샌드박스에서 막아내지 못한 보안위협에 대해 파일 내 잠재적 보안 위협 요소를 제거하고 안전한 파일로 재조합하는 기술로 악성코드 감염 위험을 사전에 방지할 수 있어 외부 보안 위협으로부터 최신 대응 기술로 손꼽힌다. 
 - 오픈 소스 프로그램 중 CDR 기법을 사용하는 'Dangerzone'은 한국에서 많이 사용되는 문서 확장자 hwp를 지원하지 않는 아쉬움이 있다. 또한, 사람들이 많이 이용하는 이메일 시스템은 자체적으로 유해 url을 차단하지 못해 실수로 접속할 우려가 있다.
 - 이러한 악성 위협들로 부터 안전한 인터넷 사용을 가능하게 하는 *"Ms Word 뿐 아니라 Hwp 확장자를 포함한 문서의 pdf 변환, URL 검사 기능과 File 감염 여부 검사가 가능한 web과 광고배너 차단기능을 가진 Chrome extension"을 개발하였다.*
 
 
 ##  핵심기능
  Ubuntu 환경에서 Python과 Django를 이용해 구현된 web  Server 환경에서 크게 4가지의 기능이 제공됩니다.
 
1. URL SCAN
    - 사용자가 브라우져 또는 이메일로 수신한 URL에 접속전 해당 URL을 스캔하여 위험도 확인
    - 악성 URL의 경우, 탐지된 malware 확인 가능
2. FILE SCAN
    - 사용자의 파일을 검사하여 malware 감염 여부 확인
    - 악성 FILE의 경우, 탐지된 malware 확인 가능
3. DangerZone 확장자 변환
    - 한글 hwp 문서 변환 시, 악성 매크로나 OLE 개체와 같은 동적 기능들이 가질 수 있는 악성 위협들 제외(삭제)하고 글 및 그림 등 본문 내용을 무손상 상태로 사용자에게 전달
    - 기존 DangerZone에서 제공 하는 기능도 모두 사용 가능
4. AD Block
    - 사이트 내 무분별한 광고 배너를 차단하여 쾌적한 사이트 이용 가능
    -  Membranes pattern, Shadow DOM bypassing 기술 



## 기대 효과
본 프로젝트의 기대효과는 3가지 측면에서 생각해 볼 수 있다. 
먼저 기술적 측면에서 악성코드를 지닌 문서 내부 데이터를 확인할 수 있고, HWP와 MS Office 등 다양한 문서 파일의 확장자 변환 기능을 제공한다는 점, 악성 사이트 차단 및 사이트 URL을 통한 위험도 확인 기능과 파일 감염 여부 화인이 가능하다.
경제적 측면으로는 크롬 확장 프로그램 방식을 사용한 광고 배너 차단 기능은 사용자에게 높은 접근성과 편리성을 제공하여 인터넷 사이트를 이용함에 사용자를 유해 광고로부터 보호 할 수 있다.무엇보다 오픈소스로 출처를 밝힌 후, 사용자의 편의에 따라 변경이 가능하다.
마지막 사회적 측면에서 APT 공격의 예방이 가능하다.

