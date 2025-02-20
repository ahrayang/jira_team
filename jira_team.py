import requests
import json
import base64
import urllib.parse
import re  # 정규 표현식을 위해 추가

# ------------------------------------------------------------------------------
# 1) 주요 변수
# ------------------------------------------------------------------------------
jira_url    = "https://alt9-sol.atlassian.net"
username    = "sheepknow@alt9.co.kr"
api_token   = "ATATT3xFfGF04mxoMtYNXAVyiCpfzUN5qZ8lU7McJO3iY10paFpmesRISwr6ntgyi4Tq3kalNPlhU6XGIUpRlrR0vG4uijsXQWUdThSCj-k2OpN6RlAKpNWPFMnFPWZghplkJtrIdYO6ndYH9Qc4cc4vlSh7SdTTMwznZ9rHbi2aJGpjGI6kbLg=B87404A2"
teamFieldId = "customfield_10001"

auth_string = f"{username}:{api_token}"
auth_bytes  = auth_string.encode("utf-8")
auth_base64 = base64.b64encode(auth_bytes).decode("utf-8")

headers = {
    "Authorization": f"Basic {auth_base64}",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

keywords = [
    "그림자", "클라우드", "퀘이크", 
    "UI", "FX", "배경 레벨", "배경 모델링", "배경 컨셉", "애니메이션", "캐릭터 모델링", "캐릭터 컨셉",
    "시스템 기획", "월드 기획", "전투 기획",
    "PM", "QA"
]

teamMap = {
    "그림자": "ddde9117-c191-4201-9e0c-667eeda52956",
    "클라우드": "a245c4cc-831b-42a6-9521-227b7c0ea151",
    "퀘이크": "40160708-ffbc-43eb-8c75-90d3e189c044",
    "UI": "d0b6b592-fb31-48fd-b461-718d6beda10c",
    "FX": "8ab4c0cc-6d6b-4330-9202-f1f4cde6ebed",
    "배경 레벨": "c0114607-8cea-4d34-a124-0d69429b477f",
    "배경 모델링": "d0e8f148-ada6-4ff9-bc4a-d6d7a1341c6b",
    "배경 컨셉": "ca79e3c9-3863-4cfd-a295-c7bf5c040a12",
    "애니메이션": "9161fdb2-fbe5-428e-9dc3-70038eea8572",
    "캐릭터 모델링": "80fef97c-8a38-4674-997c-cf0474ebb446",
    "캐릭터 컨셉": "7a0e7248-cf1f-4223-b915-4cb8688ada46",
    "시스템 기획": "b07775f8-5f75-4362-9f33-bd8c5bff8855",
    "월드 기획": "39a7e49d-2ed1-42c3-8d76-23fb1ed6976d",
    "전투 기획": "1d8d0973-5cdc-4238-9af3-0c11cd7207de",
    "PM": "aef66757-d837-4b1b-afa5-a66f6493d450",
    "QA": "923af908-fc5b-415a-b76b-37d6566a3806"
}

# ------------------------------------------------------------------------------
# 2) JQL로 이슈 목록을 페이징 검색
# ------------------------------------------------------------------------------
def searchIssues(jql, startAt, maxResults):
    encoded_jql = urllib.parse.quote(jql)
    url = f"{jira_url}/rest/api/3/search?jql={encoded_jql}&startAt={startAt}&maxResults={maxResults}"
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"❌ Search API failed: {response.status_code}, {response.text}")
        return None
    
    return response.json()

assigneeGroupsCache = {}

def getUserGroups(assigneeAccountId):
    if not assigneeAccountId:
        return None
    
    if assigneeAccountId in assigneeGroupsCache:
        return assigneeGroupsCache[assigneeAccountId]
    
    url = f"{jira_url}/rest/api/3/user/groups?accountId={assigneeAccountId}"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        print(f"❌ 그룹 조회 실패: {resp.status_code}, {resp.text}")
        assigneeGroupsCache[assigneeAccountId] = []
        return []
    
    groups = resp.json()
    assigneeGroupsCache[assigneeAccountId] = groups
    return groups

def determineTeamField(assigneeAccountId):
    if not assigneeAccountId:
        print("담당자가 없음 -> Team 필드 비움.")
        return None
    
    groupsJson = getUserGroups(assigneeAccountId)
    if not groupsJson:
        print("담당자 그룹 목록이 없으므로 Team 필드 비움.")
        return None
    
    matchedTeamName = None  # ← 추가: 초기화
    print("✅ 사용자가 속한 그룹 목록:")
    for g in groupsJson:
        groupName = g.get("name", "")
        # 공백 제거한 그룹 이름
        cleanGroupName = re.sub(r"\s+", "", groupName)
        for kw in keywords:
            # 공백 제거한 키워드와 비교
            if re.sub(r"\s+", "", kw) in cleanGroupName:
                matchedTeamName = groupName 
                break
        if matchedTeamName:
            break

    if not matchedTeamName:
        print("⚠️ 해당 사용자의 그룹 중 키워드 포함된 팀이 없음.")
        return None
    
    print(f"✅ 선택된 팀 이름: {matchedTeamName}")
    matchedTeamId = None
    for key, value in teamMap.items():
        if re.sub(r"\s+", "", key) == re.sub(r"\s+", "", matchedTeamName):
            matchedTeamId = value
            break
    if not matchedTeamId:
        print("❌ 선택된 팀 ID를 찾을 수 없음. 필드 업데이트 중단.")
        return None
    print(f"✅ 선택된 팀 ID: {matchedTeamId}")
    return matchedTeamId

# ------------------------------------------------------------------------------
# 3) Bulk Update 함수 (문제 부분만 수정)
#    기존 Bulk API 대신 개별 PUT 요청을 사용하여, 
#    실제 Groovy 스크립트처럼 "fields" 블럭을 사용해 업데이트합니다.
# ------------------------------------------------------------------------------
def bulkUpdateIssues(updates):
    overall_success = True
    for update in updates:
        issueKey = update.get("issueIdOrKey")
        url = f"{jira_url}/rest/api/3/issue/{issueKey}"
        # update 페이로드 그대로 전송 (Groovy 스크립트와 동일한 방식)
        response = requests.put(url, headers=headers, data=json.dumps(update))
        if response.status_code != 204:
            print(f"❌ Issue {issueKey} update failed: {response.status_code}, {response.text}")
            overall_success = False
        else:
            print(f"✅ Issue {issueKey} update succeeded.")
    return overall_success

# ------------------------------------------------------------------------------
# 4) 메인 실행
# ------------------------------------------------------------------------------
def main():
    # sb 프로젝트 전체
    jql = 'project = "SM7"'
    startAt = 0
    maxResults = 100
    hasMore = True
    
    print("===== 대량 이슈 업데이트 시작 =====")

    # 카운터
    total_issues_processed = 0
    team_assigned_count    = 0
    team_null_count        = 0
    bulk_fail_count        = 0

    while hasMore:
        searchResult = searchIssues(jql, startAt, maxResults)
        if not searchResult:
            print("검색 API 실패 또는 결과 없음 -> 종료.")
            break
        
        issues = searchResult.get("issues", [])
        total  = searchResult.get("total", 0)
        
        if not issues:
            print("검색된 이슈가 더 이상 없습니다. 종료합니다.")
            break
        
        print(f"현재 batch: startAt={startAt}, 가져온 이슈 수: {len(issues)}, total={total}")
        
        issueUpdates = []
        issueResultsForThisBatch = []  # list of "team" or "null"
        
        for issue in issues:
            issueKey = issue.get("key")
            fields   = issue.get("fields") or {}
            assignee = fields.get("assignee") or {}
            assigneeAccountId = assignee.get("accountId")
            
            print(f"\n이슈: {issueKey}, 담당자 ID: {assigneeAccountId}")
            teamFieldValue = determineTeamField(assigneeAccountId)
            
            if teamFieldValue:
                # Groovy 스크립트처럼 "fields" 블럭을 사용하여 업데이트
                issueUpdates.append({
                    "issueIdOrKey": issueKey,
                    "fields": {
                        teamFieldId: teamFieldValue
                    }
                })
                issueResultsForThisBatch.append("team")
            else:
                issueUpdates.append({
                    "issueIdOrKey": issueKey,
                    "update": {
                        teamFieldId: [
                            {"set": None}
                        ]
                    }
                })
                issueResultsForThisBatch.append("null")
            
            if len(issueUpdates) >= 50:
                print(f"   -> 개별 업데이트 50건 진행...")
                success = bulkUpdateIssues(issueUpdates)
                
                if success:
                    for r in issueResultsForThisBatch:
                        if r == "team":
                            team_assigned_count += 1
                        else:
                            team_null_count += 1
                else:
                    bulk_fail_count += 1
                
                total_issues_processed += len(issueUpdates)
                
                issueUpdates = []
                issueResultsForThisBatch = []
        
        if issueUpdates:
            print(f"   -> 남은 {len(issueUpdates)}건 개별 업데이트 진행...")
            success = bulkUpdateIssues(issueUpdates)
            
            if success:
                for r in issueResultsForThisBatch:
                    if r == "team":
                        team_assigned_count += 1
                    else:
                        team_null_count += 1
            else:
                bulk_fail_count += 1
            
            total_issues_processed += len(issueUpdates)
            issueUpdates = []
            issueResultsForThisBatch = []
        
        startAt += maxResults
        if startAt >= total:
            hasMore = False
    
    print("===== 대량 이슈 업데이트 완료 =====")
    print(f"총 처리된 이슈 수: {total_issues_processed}")
    print(f"    - 팀이 지정된 이슈: {team_assigned_count}")
    print(f"    - null(할당안됨) 이슈: {team_null_count}")
    print(f"    - bulk 실패 횟수: {bulk_fail_count}")

if __name__ == "__main__":
    main()
