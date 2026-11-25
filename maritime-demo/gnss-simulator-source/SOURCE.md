# GNSS 선교 전자해도 소스

`ship/maritime-cli-lab/bridge-ui`의 React-Leaflet 지도와 RMA 선교 계기를 가져와 GitHub Pages용 정적 페이지로 빌드했습니다. 읽기 전용 `?feed=` 상태 피드와 선교 화면 이동을 추가하고, 청자 화면의 재설정·공격 중지 버튼은 제거했습니다.

원본에서 가져온 RMA 구성 요소는 AGPL-3.0입니다. 원본 출처와 라이선스 전문은 `THIRD_PARTY_NOTICES.md`, `LICENSE-RMA-AGPL-3.0.txt`에 있습니다. 이 폴더에서 `npm install && npm run build`로 인접한 `gnss-simulator/`를 다시 만들 수 있습니다.
