import requests
import urllib.parse
import base64
import json
import pandas as pd

class WebScraper:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://total.comwel.or.kr"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "Content-Type": "application/json; charset=UTF-8",
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
            "Connection": "keep-alive",
            "Referer": "https://total.comwel.or.kr/",
            "Accept-Encoding": "gzip, deflate, br"
        }
        self.session.headers.update(self.headers)

    def fetch_home_page(self):
        response = self.session.get(self.base_url)
        if response.status_code != 200 or "산재보험 토탈서비스" not in response.text or "토탈서비스 서비스 사용중 오류가 발생하였습니다. <br />잠시 후 이용해 주시기 바랍니다." in response.text:
            raise Exception("Failed to fetch or validate home page")

    def issue_token(self):
        url = f"{self.base_url}/member/issueToken.do"
        response = self.session.post(url, json={})  # Assuming empty JSON payload is correct
        if "토탈서비스 서비스 사용중 오류가 발생하였습니다. <br />잠시 후 이용해 주시기 바랍니다." in response.text:
            raise Exception("Server-side error during token issuance")
        result_json = response.json()
        if result_json.get("oacxCode") != "OACX_SUCCESS" or result_json.get("resultCode") != "200":
            raise Exception("Token issuance was unsuccessful")
        return result_json.get("txId"), result_json.get("token")

    def get_provider_list(self):
        url = f"{self.base_url}/oacx/api/v1.0/provider/list"
        response = self.session.get(url)
        if response.status_code != 200:
            raise Exception("Failed to fetch provider list")
        return response.json()


    def authenticate_request(self, providerId, providerName, id, token, txId, cxId):
        url = f"{self.base_url}/oacx/api/v1.0/authen/request"
        
        providerId      = "kakao"
        providerName    = "카카오"
        id              = "kakao_v1.5"

        postObj = {
            "providerId": providerId,
            "providerName": providerName,
            "mdlAppHash": "",
            "id": id,
            "reqTxId": "",
            "deeplinkUri": "",
            "naverAppSchemeUrl": "",
            "telcoTxid": "",
            "provider": id,
            "token": token, 
            "txId": txId,
            "cxId": cxId,
            "appInfo": {
                "code": "",
                "path": "",
                "type": ""
            },
            "userInfo": {
                "isMember": False,
                # 개인정보
                "name": urllib.parse.quote(self.encode_base64('김다운')),
                "phone": urllib.parse.quote(self.encode_base64('01096399622')),
                "phone1": urllib.parse.quote(self.encode_base64('010')),
                "phone2": urllib.parse.quote(self.encode_base64('96399622')),
                "ssn1": urllib.parse.quote(self.encode_base64('881122')),
                "ssn2": urllib.parse.quote(self.encode_base64('1249119')),
                "birthday": '19881122',
                # 
                "privacy": 1,
                "terms": 1,
                "policy3": 1,
                "policy4": 1,
                "telcoTycd": "", # this.telecom
                "access_token": "",
                "token_type": "",
                "state": "",
                "mtranskeySsn2": None
            },
            "deviceInfo": {
                "code": "PC",
                "browser": "WB",
                "os": "",
                "universalLink": False
            },
            "contentInfo": {
                "signTarget": "",
                "signTargetTycd": "nonce",
                "signType": "GOV_SIMPLE_AUTH",
                "requestTitle": "",
                "requestContents": ""
            },
            "providerOptionInfo": {
                "callbackUrl" : "",
                "reqCSPhoneNo" : "1",
                "upmuGb" : "",
                "isUseTss" : "Y",
                "isNotification" : "Y",
                "isPASSVerify" : "Y",
                "isUserAgreement" : "Y"
            }, 
            "compareCI": True,
            "useMdlSsn": False
        }

        response = self.session.post(url, json=postObj)
        if response.status_code != 200:
            raise Exception("Failed to make authentication request")
        

        postObj['reqTxId'] = response.json().get('reqTxId')
        postObj['token'] = response.json().get('token')
        postObj['cxId'] = response.json().get('cxId')

        # 결과 확인 및 추가 처리
        # return response.json()
        return postObj

    def encode_base64(self, value):
        # 문자열을 bytes로 변환 후, base64로 인코딩합니다.
        encoded_bytes = base64.urlsafe_b64encode(value.encode('utf-8'))
        # 인코딩된 bytes를 다시 문자열로 변환합니다.
        encoded_str = str(encoded_bytes, 'utf-8')
        return encoded_str

    # 사용자로부터 '1' 입력 받기
    def wait_for_user_input():
        while True:
            user_input = input("Press '1' to proceed: ")
            if user_input == "1":
                return True
            else:
                print("Invalid input. Please press '1' to continue.")
                
    def authenticate_result(self, authenticate_request):    
        url = f"{self.base_url}/oacx/api/v1.0/authen/result"
        # postObj = {
        #     "reqTxId": reqTxId,
        #     "token": token,
        #     "cxId": cxId,
        # }
        
        #response = self.session.post(url, json=postObj)
        response = self.session.post(url, json=authenticate_request)
        if response.status_code != 200:
            raise Exception("Failed to get authentication result")
        return response.json()


    def parsing_token(self, token):
        MAX_RETRIES = 3
        url = f"{self.base_url}/member/parsingToken.do"
        for attempt in range(MAX_RETRIES):
            response = self.session.post(url, json={"token": token}, headers=self.headers)
            if response.ok:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    pass  # 재시도
            if attempt == MAX_RETRIES - 1:  # 마지막 시도에서도 실패한 경우
                raise Exception("Failed to parse token after maximum retries.")

    def perform_final_step(self, signed_msg, user_group_fg, menu_id, vid_msg, u_group_fg):
        url = f"{self.base_url}/member/certEasyLogin.do"
        post_data = {
            "signed_msg": signed_msg,
            "user_group_fg": user_group_fg,
            "MENU_ID": menu_id,
            "vid_msg": vid_msg,
            "u_group_fg": u_group_fg
        }
        response = self.session.post(url, json=post_data, headers=self.headers)
        if response.ok:
            try:
                return response.json()
            except json.JSONDecodeError:
                raise Exception("Failed to decode JSON from final step response.")
        else:
            raise Exception("Final step request failed with status code:", response.status_code)    


    def fetch_employment_info(self, GWANRI_NO):
        for attempt in range(3):
            url = f"{self.base_url}/w/wl/selectGeunrojaGyIryeok.do"
            data = {
                "dsInInfo": [{
                    "BOHEOM_FG": "5",
                    "GWANRI_NO": GWANRI_NO, # "11386326270",
                    "DAMDANGJA_ID": "",
                    "CHEORI_JISA_CD": "",
                    "SAEOPJANG_NM": "",
                    "JIYEOKBONBU_GWANHAL": "",
                    "GY_JOHOE_FROM_DT": "",
                    "GY_JOHOE_TO_DT": "",
                    "GY_FROM_DT": "",
                    "GY_TO_DT": "",
                    "GY_TO_FROM_DT": "",
                    "GY_TO_TO_DT": "",
                    "HYUJIK_FROM_FROM_DT": "",
                    "HYUJIK_FROM_TO_DT": "",
                    "HYUJIK_TO_FROM_DT": "",
                    "HYUJIK_TO_TO_DT": "",
                    "JEONGJEONG_YN": "",
                    "CHANGE_YN": "",
                    "SOMYEOL_YN": "",
                    "GEUNROJA_WONBU_NO": "",
                    "GS_WONBU_NO": "",
                    "JEONBO_FROM_DT": "",
                    "JEONBO_TO_DT": "",
                    "TEUKSU_JIKJONG_CD": "",
                    "GYEYAKJIK_YN": "1",
                    "GYEYAK_END_DT": "1",
                    "rowStatus": "C",
                    "GEUNROJA_RGNO": "",
                    "GEUNROJA_NM": "",
                    "GY_STATUS_CD": "",
                    "GEUNROJA_FG": "",
                    "USER_GROUP_FG": "2",
                    "SORT_FG": "1A",
                    "ST_SER": "1",
                    "ED_SER": "2000",
                    "MAX_SER": "0",
                    "SG_YN": "",
                    "SAEOPGAESI_NO": "",
                    "UN_CONFM_SUBSLY_MANAGE_NO": "",
                }]
            }
            response = self.session.post(url, headers=self.headers, json=data)
            if response.status_code == 200:
                try:
                    result_json = response.json()
                    if self._validate_response(result_json):
                        return result_json  # or any specific data extracted from result_json
                except json.JSONDecodeError:
                    pass  # 재시도

            if attempt < 2:  # 마지막 시도가 아니면 잠시 대기
                time.sleep(3)

        raise Exception("Failed to fetch employment information after 3 attempts.")

    def _validate_response(self, response_json):
        # Implement validation logic here, e.g., check status codes, messages, etc.
        # Return True if response is valid, False otherwise
        return True



# usage
scraper = WebScraper()

try:
    scraper.fetch_home_page()

    txId, token = scraper.issue_token()
    # print(f"Issued token successfully: txId={txId}, token={token}")

    provider_list = scraper.get_provider_list()
    # print("Provider List:", provider_list)

    authenticate_request = scraper.authenticate_request('kakao', '카카오', 'kakao_v1.5', token, txId, 'cxId')
    # print("authenticate_request:", authenticate_request)

# authenticate_request['token']
# authenticate_request.get('token')

    # 진행을 위한 사용자 입력 모방, 실제 사용자 입력 메커니즘으로 교체
    user_input = input("인증 결과 요청을 계속하려면 '1'을 입력하세요: ")
    if user_input == "1":
        #auth_result = scraper.authenticate_result(reqTxId, token, cxId)
        auth_result = scraper.authenticate_result(authenticate_request)
        # print("Authentication result:", auth_result)
    else:
        print("사용자에 의해 인증 결과 요청이 중단되었습니다.")

    token = auth_result.get('token')

    # print("@@token@@:", token)
    parsed_result = scraper.parsing_token(token)
    # 여기서 얻은 parsed_result의 값을 바탕으로 필요한 정보 추출
    # 예시: txId, token 등을 사용하여 다음 요청에 필요한 데이터 준비

    final_result = scraper.perform_final_step(signed_msg="auth", user_group_fg="2", menu_id="10051007", vid_msg="200", u_group_fg="1")
    print("[[ 간편인증 정상 체크 ]]]", final_result)

    # 사용자로부터 GWANRI_NO 입력 받기
    user_gwanri_no = input("관리번호를 입력하세요: ")

    employment_info = scraper.fetch_employment_info(GWANRI_NO=user_gwanri_no)
    print("[완][료]")
    # print(employment_info)
    # print("1")
    # print(filename)

    # 데이터를 pandas DataFrame으로 변환
    df = pd.DataFrame(employment_info['dsOutList'])
    filename = "/Users/codef/Desktop/employment_info.xlsx"
    # 엑셀 파일로 저장
    df.to_excel(filename, index=False)

    # 파일 저장 경로와 이름 지정
    # filename = "/Users/codef/Desktop/employment_info.txt"

    # 파일에 JSON 데이터 쓰기
    # with open(filename, 'w', encoding='utf-8') as file:
    #     # json.dump(employment_info, file, ensure_ascii=False, indent=4)

    #     # JSON 형태로 저장하려면
    #     # json.dump(employment_info['dsOutList'], file, ensure_ascii=False, indent=4)

    #     # 또는 각 객체를 한 줄에 하나씩 텍스트로 저장하려면
    #     for item in employment_info['dsOutList']:
    #         file.write(json.dumps(item, ensure_ascii=False) + '\n')
    #     print(f"JSON 데이터가 {filename}에 저장되었습니다.")



except Exception as e:
    print("An error occurred:", e)
