#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, jsonify
import subprocess
import re
import json
import os
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import time
from functools import lru_cache
import threading

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

# 프로덕션용 로깅 설정
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class PerforceWebTracker:
    def __init__(self):
        self.depot_configs = {
            'Sol Dev1Next': '//Sol/Dev1Next/...',
            'Sol Dev1': '//Sol/Dev1/...',
            'Sol Dev2': '//Sol/Dev2/...',
            'Sol Main': '//Sol/Main/...',
            'Sol Staging': '//Sol/Staging/...',
            'Sol Ash': '//Sol/Ash/...',
            'Sol Dev': '//Sol/Dev/...'
        }
        # 인코딩 캐시 (파일별 성공 인코딩 저장)
        self._encoding_cache = {}
        self._cache_lock = threading.Lock()

    # 입력 검증
    def _validate_change_num(self, change_num):
        if not re.match(r'^\d+$', str(change_num)):
            raise ValueError("Invalid changelist number")
        return str(change_num)

    def _validate_file_path(self, file_path):
        if not file_path or not isinstance(file_path, str):
            raise ValueError("Invalid file path")
        if not file_path.startswith('//'):
            raise ValueError("File path must start with //")
        return file_path

    def utc_to_kst(self, utc_str):
        try:
            dt_utc = datetime.strptime(utc_str, "%Y/%m/%d %H:%M:%S")
            dt_kst = dt_utc + timedelta(hours=9)
            return dt_kst.strftime("%Y/%m/%d %H:%M:%S")
        except Exception as e:
            logging.error(f"UTC -> KST 변환 실패: {e}")
            return utc_str

    def run_command(self, cmd_list, timeout=30):
        """인코딩 캐시 사용, 타임아웃 추가"""
        logging.debug(f"[CMD 실행]: {cmd_list}")
        
        # 파일 경로가 있으면 캐시된 인코딩 시도
        file_path = None
        for arg in cmd_list:
            if isinstance(arg, str) and arg.startswith('//'):
                file_path = arg.split('#')[0]  # 리비전 제거
                break
        
        try:
            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=False,
                check=True,
                timeout=timeout
            )
            stdout_bytes = result.stdout

            # 캐시된 인코딩부터 시도
            encodings = ['utf-8', 'utf-8-sig', 'cp949', 'euc-kr', 'latin-1']
            if file_path and file_path in self._encoding_cache:
                cached_enc = self._encoding_cache[file_path]
                encodings = [cached_enc] + [e for e in encodings if e != cached_enc]

            for enc in encodings:
                try:
                    decoded = stdout_bytes.decode(enc)
                    # 성공시 캐시 업데이트
                    if file_path and enc not in ['latin-1']:  # latin-1은 항상 성공하므로 제외
                        with self._cache_lock:
                            self._encoding_cache[file_path] = enc
                    logging.debug(f"[CMD 결과 - {enc}]: {len(decoded)} chars")
                    return decoded
                except UnicodeDecodeError:
                    continue

            decoded = stdout_bytes.decode('utf-8', errors='replace')
            logging.debug(f"[CMD 결과 - utf-8/replace]: {len(decoded)} chars")
            return decoded

        except subprocess.TimeoutExpired:
            logging.error(f"[CMD 타임아웃]: {cmd_list}")
            return ""
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode('utf-8', errors='replace') if e.stderr else ''
            logging.error(f"[CMD 실행 실패]: {err}")
            return ""

    def get_changes(self, depot, since, until, user=None):
        """입력 검증 추가"""
        # depot 경로 검증
        if depot not in self.depot_configs.values():
            return {'error': 'Invalid depot path'}
        
        base = ['p4', 'changes']
        if user:
            # 사용자명 검증 (영숫자, @, - 등만 허용)
            if not re.match(r'^[a-zA-Z0-9@._-]+$', user):
                return {'error': 'Invalid user name'}
            base += ['-u', user]
        base.append(f'{depot}@{since},{until}')

        output = self.run_command(base)
        if not output:
            return {'error': 'Perforce 명령어 실행 실패 또는 결과 없음'}

        changes = []
        pattern = re.compile(r"^Change\s+(\d+)\s+on\s+(\d{4}/\d{2}/\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)\s+by\s+(\S+)")
        for line in output.splitlines():
            m = re.search(pattern, line.strip())
            if m:
                change_num = m.group(1)
                date_time = m.group(2)
                user_name = m.group(3)
                if user_name.lower().startswith("jenkins"):
                    continue
                changes.append({'change': change_num, 'date': date_time, 'user': user_name})
        return changes

    def parse_describe_grouped(self, change_num):
        """입력 검증 및 파일 크기 체크 추가"""
        change_num = self._validate_change_num(change_num)
        
        output = self.run_command(['p4', 'describe', '-s', change_num])
        if not output:
            return {'error': f'Change {change_num} 상세 정보 조회 실패'}

        # 대용량 출력 체크 (10MB 제한)
        if len(output) > 10 * 1024 * 1024:
            return {'error': 'Change 정보가 너무 큽니다'}

        lines = output.splitlines()
        header_pattern = re.compile(r"^Change\s+\d+\s+by\s+(\S+)@.*\s+on\s+(\d{4}/\d{2}/\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)")
        header_found = False
        description_lines = []
        in_affected = False
        action_to_files = defaultdict(list)
        user, submit_time = "", ""

        for line in lines:
            if not header_found:
                m = re.search(header_pattern, line.strip())
                if m:
                    user = m.group(1)
                    submit_time = m.group(2)
                    if " " not in submit_time:
                        submit_time += " 00:00:00"
                    header_found = True
                continue

            if not in_affected:
                if "Affected files" in line:
                    in_affected = True
                    continue
                else:
                    description_lines.append(line.rstrip())
            else:
                if line.strip() == "":
                    continue
                m = re.match(r"^\s*\.\.\.\s+(//\S+)#(\d+)\s+(\w+)", line)
                if m:
                    depot_path = m.group(1)
                    rev = m.group(2)
                    action = m.group(3).lower()
                    file_name = os.path.basename(depot_path)
                    if file_name.lower().endswith('.json'):
                        action_to_files[action].append({
                            'path': depot_path,
                            'filename': file_name,
                            'rev': rev
                        })

        description = "\n".join(description_lines).strip()
        jira_urls = re.findall(r'(https?://\S+atlassian\.net\S+)', description)
        jira_combined = ", ".join(jira_urls)

        converted_time = self.utc_to_kst(submit_time)
        date_part, time_part = converted_time.split(" ") if " " in converted_time else (converted_time, "")

        if not any(action_to_files.values()):
            return None

        return {
            'change_num': change_num,
            'user': user,
            'date': date_part,
            'time': time_part,
            'description': description,
            'jira_urls': jira_combined,
            'actions': action_to_files
        }

    def get_prev_curr_contents(self, file_path, rev=None):
        """파일 크기 체크 추가"""
        file_path = self._validate_file_path(file_path)
        
        if rev:
            try:
                r = int(rev)
                prev_rev = str(r - 1)
                curr_rev = str(r)
            except:
                prev_rev, curr_rev = None, None
        else:
            flog = self.run_command(['p4', 'filelog', '-m2', file_path])
            if not flog:
                return None, None, None, None
            versions = re.findall(r'#(\d+)', flog)
            if len(versions) < 2:
                return None, None, None, None
            curr_rev, prev_rev = versions[0], versions[1]

        if not prev_rev or not curr_rev:
            return None, None, None, None

        prev_content = self.run_command(['p4', 'print', '-q', f'{file_path}#{prev_rev}'])
        curr_content = self.run_command(['p4', 'print', '-q', f'{file_path}#{curr_rev}'])
        
        # 파일 크기 체크 (각각 5MB 제한)
        if len(prev_content) > 5 * 1024 * 1024 or len(curr_content) > 5 * 1024 * 1024:
            logging.warning(f"Large file detected: {file_path}")
            return None, None, None, None
            
        return prev_content, curr_content, prev_rev, curr_rev

    def compare_json_content(self, prev_content, curr_content, force_nochange_row=False):
        """메모리 사용량 최적화"""
        try:
            if prev_content is None or curr_content is None:
                return [{"type": "error", "path": "<root>", "old_value": None, "new_value": None,
                         "message": "파일 내용을 가져올 수 없습니다"}]

            prev_content = prev_content.strip()
            curr_content = curr_content.strip()
            if not prev_content and not curr_content:
                return [{"type": "error", "path": "<root>", "old_value": None, "new_value": None,
                         "message": "파일 내용이 비어있습니다"}]

            try:
                prev_data = json.loads(prev_content)
                curr_data = json.loads(curr_content)
            except json.JSONDecodeError as e:
                return [{"type": "error", "path": "<root>", "old_value": None, "new_value": None,
                         "message": f"JSON 파싱 오류: {str(e)}"}]

            changes = []
            self._find_json_changes(prev_data, curr_data, "", changes)

            if not changes and force_nochange_row:
                changes.append({
                    "type": "nochange",
                    "path": "<root>",
                    "old_value": "No changes",
                    "new_value": "No changes"
                })

            # 50명 동시 사용 고려하여 제한 강화
            return changes[:200]

        except Exception as e:
            logging.error(f"compare_json_content 오류: {e}")
            return [{"type": "error", "path": "<root>", "old_value": None, "new_value": None,
                     "message": "비교 중 오류 발생"}]

    def _find_json_changes(self, prev_data, curr_data, path, changes):
        # if len(changes) > 200:
        #     return
        if type(prev_data) != type(curr_data):
            changes.append({
                "type": "modified",
                "path": path or "<root>",
                "old_value": prev_data,
                "new_value": curr_data
            })
            return

        if isinstance(prev_data, dict):
            all_keys = set(prev_data.keys()) | set(curr_data.keys())
            for k in all_keys:
                # if len(changes) > 200:
                #     break
                new_path = f"{path}.{k}" if path else k
                
                # 이 부분은 그대로 유지:
                if k not in prev_data:
                    changes.append({"type": "added", "path": new_path,
                                    "old_value": None, "new_value": curr_data[k]})
                elif k not in curr_data:
                    changes.append({"type": "removed", "path": new_path,
                                    "old_value": prev_data[k], "new_value": None})
                else:
                    self._find_json_changes(prev_data[k], curr_data[k], new_path, changes)
            return

        if isinstance(prev_data, list):
            prev_dicts = [x for x in prev_data if isinstance(x, dict)]
            curr_dicts = [x for x in curr_data if isinstance(x, dict)]
            if prev_dicts or curr_dicts:
                candidate_keys = ["rid", "id", "quest_id", "skill_id",
                                  "monster_id", "npc_id", "code", "key", "name"]
                use_key = None

                if prev_dicts and curr_dicts:
                    best_key = None
                    best_score = -1
                    for k in candidate_keys:
                        score = sum(1 for x in prev_dicts if k in x) + sum(1 for y in curr_dicts if k in y)
                        if score > best_score:
                            best_key = k
                            best_score = score
                    if best_key and (any(best_key in x for x in prev_dicts) or any(best_key in y for y in curr_dicts)):
                        use_key = best_key

                if use_key:
                    prev_map = {str(d.get(use_key)): d for d in prev_dicts if use_key in d}
                    curr_map = {str(d.get(use_key)): d for d in curr_dicts if use_key in d}
                    all_ids = set(prev_map.keys()) | set(curr_map.keys())
                    for idv in all_ids:
                        if len(changes) > 200:
                            break
                        new_path = f"{path}[{use_key}={idv}]" if path else f"[{use_key}={idv}]"
                        if idv not in prev_map:
                            changes.append({"type": "added", "path": new_path,
                                            "old_value": None, "new_value": curr_map[idv]})
                        elif idv not in curr_map:
                            changes.append({"type": "removed", "path": new_path,
                                            "old_value": prev_map[idv], "new_value": None})
                        else:
                            self._find_json_changes(prev_map[idv], curr_map[idv], new_path, changes)
                    return

            if all(not isinstance(x, (dict, list)) for x in prev_data + curr_data):
                prev_cnt = Counter(prev_data)
                curr_cnt = Counter(curr_data)
                for val, cnt in (prev_cnt - curr_cnt).items():
                    for _ in range(min(cnt, 50)):  # 제한
                        if len(changes) > 200:
                            return
                        changes.append({
                            "type": "removed",
                            "path": path or "<root>",
                            "old_value": val,
                            "new_value": None
                        })
                for val, cnt in (curr_cnt - prev_cnt).items():
                    for _ in range(min(cnt, 50)):  # 제한
                        if len(changes) > 200:
                            return
                        changes.append({
                            "type": "added",
                            "path": path or "<root>",
                            "old_value": None,
                            "new_value": val
                        })
                return

            max_len = min(max(len(prev_data), len(curr_data)), 100)  # 배열 크기 제한
            for i in range(max_len):
                if len(changes) > 200:
                    break
                new_path = f"{path}[{i}]"
                if i >= len(prev_data):
                    changes.append({"type": "added", "path": new_path,
                                    "old_value": None, "new_value": curr_data[i]})
                elif i >= len(curr_data):
                    changes.append({"type": "removed", "path": new_path,
                                    "old_value": prev_data[i], "new_value": None})
                else:
                    self._find_json_changes(prev_data[i], curr_data[i], new_path, changes)
            return

        if prev_data != curr_data:
            changes.append({
                "type": "modified",
                "path": path or "<root>",
                "old_value": prev_data,
                "new_value": curr_data
            })

    def get_json_diff(self, file_path, change_num=None, rev=None, force_nochange_row=False):
        try:
            prev, curr, prev_rev, curr_rev = self.get_prev_curr_contents(file_path, rev=rev)
            if prev is None and curr is None:
                return {
                    'file': file_path,
                    'has_changes': False,
                    'changes': [{"type": "error", "path": "<root>",
                                 "message": "파일 히스토리를 가져올 수 없습니다"}]
                }
            changes = self.compare_json_content(prev, curr, force_nochange_row=force_nochange_row)
            has_real = any(c.get('type') in ('added', 'removed', 'modified') for c in changes)
            return {
                'file': file_path,
                'prev_version': prev_rev or '',
                'curr_version': curr_rev or '',
                'changes': changes,
                'has_changes': has_real
            }
        except Exception as e:
            logging.error(f"JSON Diff 조회 실패 {file_path}: {e}")
            return {
                'file': file_path,
                'has_changes': False,
                'changes': [{"type": "error", "path": "<root>", "message": "예상치 못한 오류"}]
            }

tracker = PerforceWebTracker()

@app.route('/')
def index():
    return render_template('index.html', depots=list(tracker.depot_configs.keys()))

@app.route('/api/search', methods=['POST'])
def search_changes():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
            
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        selected_depots = data.get('depots', [])
        user_filter = data.get('user_filter', '')

        # 입력 검증
        if not start_date or not end_date or not selected_depots:
            return jsonify({'error': 'Missing required parameters'}), 400

        # 날짜 형식 처리 개선
        def format_perforce_date(date_str):
            try:
                if '/' in date_str and ':' in date_str and len(date_str.split(':')) >= 3:
                    return date_str
                if 'T' in date_str:
                    dt = datetime.fromisoformat(date_str.replace('T', ' '))
                    return dt.strftime('%Y/%m/%d:%H:%M:%S')
                return date_str.replace('-', '/') + ':00:00:00'
            except Exception as e:
                logging.error(f"Date format error: {e}")
                return date_str.replace('-', '/') + ':00:00:00'
        
        start_datetime = format_perforce_date(start_date)
        end_datetime = format_perforce_date(end_date)
        
        print(f"DEBUG: 변환된 날짜 - start: {start_datetime}, end: {end_datetime}")

        all_results = {}

        for depot_name in selected_depots:
            if depot_name not in tracker.depot_configs:
                continue

            depot_path = tracker.depot_configs[depot_name]
            changes = tracker.get_changes(
                depot_path, start_datetime, end_datetime,
                user_filter if user_filter else None
            )

            if isinstance(changes, dict) and 'error' in changes:
                all_results[depot_name] = changes
                continue

            valid_changes = []
            for change in changes:
                change_detail = tracker.parse_describe_grouped(change['change'])
                if change_detail and 'error' not in change_detail:
                    files_info = []
                    for action, files in change_detail['actions'].items():
                        for file_info in files:
                            files_info.append({
                                'path': file_info['path'],
                                'filename': file_info['filename'],
                                'action': action,
                                'change_num': change_detail['change_num'],
                                'rev': file_info.get('rev', '')
                            })
                    if files_info:
                        change_detail['files'] = files_info
                        valid_changes.append(change_detail)

            user_groups = []
            if valid_changes:
                current_user = None
                current_group = None
                for change in valid_changes:
                    if change['user'] != current_user:
                        if current_group:
                            user_groups.append(current_group)
                        current_user = change['user']
                        current_group = {
                            'user': current_user,
                            'changes': [change],
                            'total_changes': 1
                        }
                    else:
                        current_group['changes'].append(change)
                        current_group['total_changes'] += 1
                if current_group:
                    user_groups.append(current_group)

            depot_result = {}
            for group in user_groups:
                depot_result[group['user']] = {
                    'user': group['user'],
                    'total_changes': group['total_changes'],
                    'changes': group['changes']
                }

            all_results[depot_name] = depot_result

        return jsonify(all_results)
        
    except Exception as e:
        logging.error(f"Search API error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/get-diff', methods=['POST'])
def get_individual_diff():
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
           
        file_path = data.get('file_path') or data.get('path')
        rev = data.get('rev')
        changelist = data.get('changelist')
        force_nochange_row = bool(data.get('force_nochange_row', False))
        
        # 디버그 로그 추가
        print(f"DEBUG: get_individual_diff 요청 - file_path: {file_path}, rev: {rev}, changelist: {changelist}")
        
        if not file_path or not file_path.lower().endswith('.json'):
            return jsonify({'success': False, 'error': 'JSON 파일만 조회 가능'}), 400
            
        diff_info = tracker.get_json_diff(file_path, change_num=changelist, rev=rev, force_nochange_row=force_nochange_row)
        
        # 디버그 로그 추가
        print(f"DEBUG: tracker.get_json_diff 결과: {diff_info is not None}")
        if diff_info:
            changes_count = len(diff_info.get('changes', []))
            print(f"DEBUG: 변경사항 개수: {changes_count}")
            if changes_count < 5:
                print(f"DEBUG: 변경사항 내용: {diff_info.get('changes', [])}")
        
        if not diff_info:
            print("DEBUG: diff_info가 None임")
            return jsonify({'success': False, 'error': '파일 정보를 가져올 수 없습니다'})
            
        real_changes = [c for c in diff_info.get('changes', []) if c.get('type') in ('added', 'removed', 'modified')]
        print(f"DEBUG: 실제 변경사항 개수: {len(real_changes)}")
        
        return jsonify({
            'success': True,
            'changes': diff_info.get('changes', []),
            'prev_version': diff_info.get('prev_version', ''),
            'curr_version': diff_info.get('curr_version', ''),
            'file_path': file_path,
            'has_real_changes': len(real_changes) > 0
        })
       
    except Exception as e:
        print(f"DEBUG: get_individual_diff 예외: {str(e)}")
        import traceback
        print(f"DEBUG: 스택트레이스: {traceback.format_exc()}")
        logging.error(f"Diff API error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

def create_templates():
    os.makedirs('templates', exist_ok=True)

if __name__ == '__main__':
    create_templates()
    print("Sol Project - Perforce 변경사항 조회 웹 서버를 시작합니다...")
    print("http://127.0.0.1:5001 에서 접속하세요")
    app.run(debug=False, host='0.0.0.0', port=5001, threaded=True)