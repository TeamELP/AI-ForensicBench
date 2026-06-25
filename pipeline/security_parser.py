import pandas as pd
import json
import uuid
import os
import re

from datetime import datetime, timezone, timedelta

# =========================
# 설정
# =========================

INPUT_FILE = os.environ.get("INPUT_FILE", "security_events.csv")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "normalized_security.json")

KST = timezone(timedelta(hours=9))

# =========================
# 안전한 int 변환
# =========================

def safe_int(value):

    try:
        return int(value)
    except:
        return None

# =========================
# hex PID 변환
# =========================

def safe_hex_to_int(value):

    if not value:
        return None

    try:

        value = str(value).strip()

        if value.startswith("0x"):
            return int(value, 16)

        return int(value)

    except:
        return None

# =========================
# Timestamp 정규화
# =========================

def normalize_timestamp(ts):

    if not ts:
        return None

    ts = str(ts).strip()

    try:

        ts = ts.replace("오전", "AM")
        ts = ts.replace("오후", "PM")

        dt = datetime.strptime(
            ts,
            "%Y-%m-%d %p %I:%M:%S"
        )

        dt = dt.replace(
            tzinfo=KST
        )

        return dt.isoformat()

    except Exception as e:

        print(f"[TIME ERROR] {ts} | {e}")

        return None

# =========================
# Artifact 생성
# =========================

def make_artifact(artifact_type, value):

    return {
        "type": artifact_type,
        "value": value
    }

# =========================
# Regex field 추출
# =========================

def extract_field(pattern, text):

    match = re.search(
        pattern,
        str(text),
        re.MULTILINE | re.DOTALL
    )

    if match:
        return match.group(1).strip()

    return None

# =========================
# Privilege 추출
# =========================

def extract_privileges(text):

    privileges = re.findall(
        r"(Se[A-Za-z]+Privilege)",
        str(text)
    )

    return list(set(privileges))

# =========================
# 공통 Event 구조
# =========================

def base_event(row):

    return {

        "evidence_id": str(uuid.uuid4()),

        "timestamp": normalize_timestamp(
            row["TimeCreated"]
        ),

        "source": "security",

        "raw_event_id": int(row["Id"]),

        "event_type": None,

        "process_name": None,
        "process_path": None,

        "pid": None,
        "parent_pid": None,

        "command_line": None,

        "user": None,

        "file_path": None,

        "destination_ip": None,
        "destination_port": None,

        "artifacts": [],

        "additional_fields": {}
    }

# =========================
# Event 4624
# =========================

def parse_event_4624(row):

    message = row["Message"]

    event = base_event(row)

    logon_type = extract_field(
        r"로그온 유형:\s*(\d+)",
        message
    )

    if logon_type == "2":
        event["event_type"] = "interactive_logon"

    elif logon_type == "3":
        event["event_type"] = "network_logon"

    elif logon_type == "5":
        event["event_type"] = "service_logon"

    elif logon_type == "10":
        event["event_type"] = "remote_interactive_logon"

    else:
        event["event_type"] = "logon_success"

    new_logon_section = extract_field(
        r"새 로그온:(.*?)프로세스 정보:",
        message
    )

    if new_logon_section:

        account_name = extract_field(
            r"계정 이름:\s*([^\n\r]+)",
            new_logon_section
        )

        account_domain = extract_field(
            r"계정 도메인:\s*([^\n\r]+)",
            new_logon_section
        )

        if account_name and account_domain:

            event["user"] = (
                f"{account_domain}\\{account_name}"
            )

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    pid = extract_field(
        r"프로세스 ID:\s*(0x[a-fA-F0-9]+)",
        message
    )

    event["pid"] = safe_hex_to_int(pid)

    source_ip = extract_field(
        r"원본 네트워크 주소:\s*([^\n\r]+)",
        message
    )

    if source_ip == "-":
        source_ip = None

    event["destination_ip"] = source_ip

    source_port = extract_field(
        r"원본 포트:\s*([^\n\r]+)",
        message
    )

    if source_port == "-":
        source_port = None

    event["destination_port"] = safe_int(
        source_port
    )

    if source_ip:

        event["artifacts"].append(
            make_artifact(
                "ip",
                source_ip
            )
        )

    event["additional_fields"] = {

        "logon_type":
            logon_type,

        "workstation_name":
            extract_field(
                r"워크스테이션 이름:\s*([^\n\r]+)",
                message
            ),

        "logon_process":
            extract_field(
                r"로그온 프로세스:\s*([^\n\r]+)",
                message
            ),

        "authentication_package":
            extract_field(
                r"인증 패키지:\s*([^\n\r]+)",
                message
            )
    }

    return event

# =========================
# Event 4656
# =========================

def parse_event_4656(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "object_access"

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    pid = extract_field(
        r"프로세스 ID:\s*(0x[a-fA-F0-9]+)",
        message
    )

    event["pid"] = safe_hex_to_int(pid)

    file_path = extract_field(
        r"개체 이름:\s*([^\n\r]+)",
        message
    )

    event["file_path"] = file_path

    if file_path:

        event["artifacts"].append(
            make_artifact(
                "file",
                file_path
            )
        )

    event["additional_fields"] = {

        "access_mask":
            extract_field(
                r"액세스 마스크:\s*([^\n\r]+)",
                message
            )
    }

    return event

# =========================
# Event 4657
# Registry Value Modified
# =========================

def parse_event_4657(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "registry_value_modified"

    registry_path = extract_field(
        r"개체 이름:\s*([^\n\r]+)",
        message
    )

    value_name = extract_field(
        r"개체 값 이름:\s*([^\n\r]+)",
        message
    )

    if registry_path and value_name:

        event["file_path"] = (
            f"{registry_path}\\{value_name}"
        )

        event["artifacts"].append(
            make_artifact(
                "registry",
                event["file_path"]
            )
        )

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:

        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    pid = extract_field(
        r"Process ID:\s*(0x[a-fA-F0-9]+)",
        message
    )

    event["pid"] = safe_hex_to_int(pid)

    new_value = extract_field(
        r"새 값:\s*([^\n\r]+)",
        message
    )

    if new_value and "powershell" in new_value.lower():

        event["event_type"] = (
            "registry_persistence"
        )

    event["additional_fields"] = {

        "registry_path":
            registry_path,

        "registry_value_name":
            value_name,

        "operation_type":
            extract_field(
                r"작업 유형:\s*([^\n\r]+)",
                message
            ),

        "new_value":
            new_value
    }

    return event

# =========================
# Event 4658
# =========================

def parse_event_4658(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "handle_close"

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    pid = extract_field(
        r"프로세스 ID:\s*(0x[a-fA-F0-9]+)",
        message
    )

    event["pid"] = safe_hex_to_int(pid)

    return event

# =========================
# Event 4659
# =========================

def parse_event_4659(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "delete_request"

    file_path = extract_field(
        r"개체 이름:\s*([^\n\r]+)",
        message
    )

    event["file_path"] = file_path

    if file_path:

        event["artifacts"].append(
            make_artifact(
                "file",
                file_path
            )
        )

    return event

# =========================
# Event 4660
# =========================

def parse_event_4660(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "object_delete"

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    return event

# =========================
# Event 4663
# =========================

def parse_event_4663(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "file_access"

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    pid = extract_field(
        r"프로세스 ID:\s*(0x[a-fA-F0-9]+)",
        message
    )

    event["pid"] = safe_hex_to_int(pid)

    file_path = extract_field(
        r"개체 이름:\s*([^\n\r]+)",
        message
    )

    event["file_path"] = file_path

    if file_path:

        event["artifacts"].append(
            make_artifact(
                "file",
                file_path
            )
        )

    return event

# =========================
# Event 4672
# =========================

def parse_event_4672(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "privileged_logon"

    event["additional_fields"] = {

        "privileges":
            extract_privileges(message)
    }

    return event

# =========================
# Event 4673
# =========================

def parse_event_4673(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "privileged_service_call"

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    event["additional_fields"] = {

        "privileges":
            extract_privileges(message)
    }

    return event

# =========================
# Event 4674
# =========================

def parse_event_4674(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "privileged_object_operation"

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    event["additional_fields"] = {

        "privileges":
            extract_privileges(message)
    }

    return event

# =========================
# Event 4688
# =========================

def parse_event_4688(row):

    message = row["Message"]

    event = base_event(row)

    process_path = extract_field(
        r"새 프로세스 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    process_lower = str(
        event["process_name"]
    ).lower()

    if process_lower == "powershell.exe":

        event["event_type"] = (
            "powershell_execution"
        )

    elif process_lower == "cmd.exe":

        event["event_type"] = (
            "shell_execution"
        )

    else:

        event["event_type"] = (
            "process_create"
        )

    pid = extract_field(
        r"새 프로세스 ID:\s*(0x[a-fA-F0-9]+)",
        message
    )

    event["pid"] = safe_hex_to_int(pid)

    parent_pid = extract_field(
        r"생성자 프로세스 ID:\s*(0x[a-fA-F0-9]+)",
        message
    )

    event["parent_pid"] = safe_hex_to_int(
        parent_pid
    )

    return event

# =========================
# Event 4690
# =========================

def parse_event_4690(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "handle_duplicate"

    event["additional_fields"] = {

        "source_process_id":
            safe_hex_to_int(
                extract_field(
                    r"원본 프로세스 ID:\s*(0x[a-fA-F0-9]+)",
                    message
                )
            ),

        "target_process_id":
            safe_hex_to_int(
                extract_field(
                    r"대상 프로세스 ID:\s*(0x[a-fA-F0-9]+)",
                    message
                )
            )
    }

    return event

# =========================
# Event 4698
# Scheduled Task Created
# =========================

def parse_event_4698(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "scheduled_task_created"
    )

    task_name = extract_field(
        r"작업 이름:\s*([^\n\r]+)",
        message
    )

    if task_name:

        event["file_path"] = task_name

        event["artifacts"].append(
            make_artifact(
                "scheduled_task",
                task_name
            )
        )

    command = extract_field(
        r"<Command>(.*?)</Command>",
        message
    )

    if command:

        event["process_name"] = os.path.basename(
            command
        ).lower()

        event["process_path"] = command

    if command and "powershell" in command.lower():

        event["event_type"] = (
            "scheduled_task_persistence"
        )

    event["additional_fields"] = {

        "task_name":
            task_name,

        "command":
            command,

        "client_process_id":
            safe_int(
                extract_field(
                    r"ClientProcessId:\s*([0-9]+)",
                    message
                )
            ),

        "parent_process_id":
            safe_int(
                extract_field(
                    r"ParentProcessId:\s*([0-9]+)",
                    message
                )
            )
    }

    return event

# =========================
# Event 4699
# Scheduled Task Deleted
# =========================

def parse_event_4699(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "scheduled_task_deleted"
    )

    task_name = extract_field(
        r"작업 이름:\s*([^\n\r]+)",
        message
    )

    if task_name:

        event["file_path"] = task_name

        event["artifacts"].append(
            make_artifact(
                "scheduled_task",
                task_name
            )
        )

    client_pid = safe_int(
        extract_field(
            r"ClientProcessId:\s*([0-9]+)",
            message
        )
    )

    parent_pid = safe_int(
        extract_field(
            r"ParentProcessId:\s*([0-9]+)",
            message
        )
    )

    event["pid"] = client_pid

    event["parent_pid"] = parent_pid

    event["additional_fields"] = {

        "task_name":
            task_name,

        "client_process_id":
            client_pid,

        "parent_process_id":
            parent_pid,

        "process_creation_time":
            extract_field(
                r"ProcessCreationTime:\s*([0-9]+)",
                message
            )
    }

    return event

# =========================
# Event 4907
# =========================

def parse_event_4907(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "audit_policy_change"

    file_path = extract_field(
        r"개체 이름:\s*([^\n\r]+)",
        message
    )

    event["file_path"] = file_path

    return event

# =========================
# Event 5156
# =========================

def parse_event_5156(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "network_connection_allowed"

    process_path = extract_field(
        r"응용 프로그램 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    event["destination_ip"] = extract_field(
        r"대상 주소:\s*([^\n\r]+)",
        message
    )

    event["destination_port"] = safe_int(
        extract_field(
            r"대상 포트:\s*([0-9]+)",
            message
        )
    )

    return event

# =========================
# Event 5158
# =========================

def parse_event_5158(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "local_port_bind"

    process_path = extract_field(
        r"응용 프로그램 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:
        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    return event

# =========================
# Event 5379
# =========================

def parse_event_5379(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "credential_access"

    if "열거" in message:

        event["event_type"] = (
            "credential_enumeration"
        )

    return event

# =========================
# Event 4625
# Failed Logon
# =========================

def parse_event_4625(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "logon_failed"

    failed_section = extract_field(
        r"로그온을 실패한 계정:(.*?)오류 정보:",
        message
    )

    if failed_section:

        account_name = extract_field(
            r"계정 이름:\s*([^\n\r]+)",
            failed_section
        )

        account_domain = extract_field(
            r"계정 도메인:\s*([^\n\r]*)",
            failed_section
        )

        if account_name:

            if account_domain:
                event["user"] = (
                    f"{account_domain}\\{account_name}"
                )
            else:
                event["user"] = account_name

    source_ip = extract_field(
        r"원본 네트워크 주소:\s*([^\n\r]+)",
        message
    )

    event["destination_ip"] = source_ip

    event["destination_port"] = safe_int(
        extract_field(
            r"원본 포트:\s*([0-9]+)",
            message
        )
    )

    if source_ip:

        event["artifacts"].append(
            make_artifact(
                "ip",
                source_ip
            )
        )

    event["additional_fields"] = {

        "failure_reason":
            extract_field(
                r"오류 이유:\s*([^\n\r]+)",
                message
            ),

        "status":
            extract_field(
                r"상태:\s*([^\n\r]+)",
                message
            ),

        "sub_status":
            extract_field(
                r"하위 상태:\s*([^\n\r]+)",
                message
            ),

        "logon_type":
            extract_field(
                r"로그온 유형:\s*([0-9]+)",
                message
            )
    }

    return event


# =========================
# Event 4634
# Logoff
# =========================

def parse_event_4634(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "logoff"

    subject_section = extract_field(
        r"주체:(.*?)로그온 유형:",
        message
    )

    if subject_section:

        account_name = extract_field(
            r"계정 이름:\s*([^\n\r]+)",
            subject_section
        )

        account_domain = extract_field(
            r"계정 도메인:\s*([^\n\r]+)",
            subject_section
        )

        if account_name and account_domain:

            event["user"] = (
                f"{account_domain}\\{account_name}"
            )

    event["additional_fields"] = {

        "logon_type":
            extract_field(
                r"로그온 유형:\s*([0-9]+)",
                message
            )
    }

    return event


# =========================
# Event 4648
# Explicit Credential Use
# =========================

def parse_event_4648(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "explicit_credential_logon"
    )

    credential_section = extract_field(
        r"자격 증명이 사용된 계정:(.*?)대상 서버:",
        message
    )

    if credential_section:

        account_name = extract_field(
            r"계정 이름:\s*([^\n\r]+)",
            credential_section
        )

        event["user"] = account_name

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]*)",
        message
    )

    event["process_path"] = process_path

    if process_path:

        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    event["destination_ip"] = extract_field(
        r"네트워크 주소:\s*([^\n\r]+)",
        message
    )

    event["destination_port"] = safe_int(
        extract_field(
            r"포트:\s*([0-9]+)",
            message
        )
    )

    return event

# =========================
# Event 4702
# Scheduled Task Updated
# =========================

def parse_event_4702(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "scheduled_task_updated"
    )

    task_name = extract_field(
        r"작업 이름:\s*([^\n\r]+)",
        message
    )

    if task_name:

        event["file_path"] = task_name

        event["artifacts"].append(
            make_artifact(
                "scheduled_task",
                task_name
            )
        )

    command = extract_field(
        r"<Command>(.*?)</Command>",
        message
    )

    if command:

        event["process_name"] = os.path.basename(
            command
        ).lower()

        event["process_path"] = command

    event["additional_fields"] = {

        "task_name":
            task_name,

        "command":
            command,

        "client_process_id":
            safe_int(
                extract_field(
                    r"ClientProcessId:\s*([0-9]+)",
                    message
                )
            ),

        "parent_process_id":
            safe_int(
                extract_field(
                    r"ParentProcessId:\s*([0-9]+)",
                    message
                )
            )
    }

    return event


# =========================
# Event 4720
# User Account Created
# =========================

def parse_event_4720(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "user_account_created"

    new_account_section = extract_field(
        r"새 계정:(.*?)특성:",
        message
    )

    if new_account_section:

        account_name = extract_field(
            r"계정 이름:\s*([^\n\r]+)",
            new_account_section
        )

        account_domain = extract_field(
            r"계정 도메인:\s*([^\n\r]+)",
            new_account_section
        )

        if account_name and account_domain:

            event["user"] = (
                f"{account_domain}\\{account_name}"
            )

    return event


# =========================
# Event 4722
# User Account Enabled
# =========================

def parse_event_4722(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "user_account_enabled"

    target_section = extract_field(
        r"대상 계정:(.*)",
        message
    )

    if target_section:

        account_name = extract_field(
            r"계정 이름:\s*([^\n\r]+)",
            target_section
        )

        account_domain = extract_field(
            r"계정 도메인:\s*([^\n\r]+)",
            target_section
        )

        if account_name and account_domain:

            event["user"] = (
                f"{account_domain}\\{account_name}"
            )

    return event


# =========================
# Event 4724
# Password Reset
# =========================

def parse_event_4724(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "password_reset"

    target_section = extract_field(
        r"대상 계정:(.*)",
        message
    )

    if target_section:

        account_name = extract_field(
            r"계정 이름:\s*([^\n\r]+)",
            target_section
        )

        account_domain = extract_field(
            r"계정 도메인:\s*([^\n\r]+)",
            target_section
        )

        if account_name and account_domain:

            event["user"] = (
                f"{account_domain}\\{account_name}"
            )

    return event


# =========================
# Event 4726
# User Account Deleted
# =========================

def parse_event_4726(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "user_account_deleted"

    target_section = extract_field(
        r"대상 계정:(.*?)추가 정보:",
        message
    )

    if target_section:

        account_name = extract_field(
            r"계정 이름:\s*([^\n\r]+)",
            target_section
        )

        account_domain = extract_field(
            r"계정 도메인:\s*([^\n\r]+)",
            target_section
        )

        if account_name and account_domain:

            event["user"] = (
                f"{account_domain}\\{account_name}"
            )

    return event


# =========================
# Event 4728
# Global Group Add
# =========================

def parse_event_4728(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = "global_group_member_added"

    event["additional_fields"] = {

        "group_name":
            extract_field(
                r"그룹 이름:\s*([^\n\r]+)",
                message
            )
    }

    return event


# =========================
# Event 4729
# Global Group Remove
# =========================

def parse_event_4729(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "global_group_member_removed"
    )

    event["additional_fields"] = {

        "group_name":
            extract_field(
                r"그룹 이름:\s*([^\n\r]+)",
                message
            )
    }

    return event


# =========================
# Event 4732
# Local Group Add
# =========================

def parse_event_4732(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "local_group_member_added"
    )

    event["additional_fields"] = {

        "group_name":
            extract_field(
                r"그룹 이름:\s*([^\n\r]+)",
                message
            )
    }

    return event


# =========================
# Event 4733
# Local Group Remove
# =========================

def parse_event_4733(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "local_group_member_removed"
    )

    event["additional_fields"] = {

        "group_name":
            extract_field(
                r"그룹 이름:\s*([^\n\r]+)",
                message
            )
    }

    return event


# =========================
# Event 4738
# User Account Changed
# =========================

def parse_event_4738(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "user_account_changed"
    )

    target_section = extract_field(
        r"대상 계정:(.*?)변경된 특성:",
        message
    )

    if target_section:

        account_name = extract_field(
            r"계정 이름:\s*([^\n\r]+)",
            target_section
        )

        account_domain = extract_field(
            r"계정 도메인:\s*([^\n\r]+)",
            target_section
        )

        if account_name and account_domain:

            event["user"] = (
                f"{account_domain}\\{account_name}"
            )

    return event


# =========================
# Event 4776
# Credential Validation
# =========================

def parse_event_4776(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "credential_validation"
    )

    event["user"] = extract_field(
        r"로그온 계정:\s*([^\n\r]+)",
        message
    )

    event["additional_fields"] = {

        "authentication_package":
            extract_field(
                r"인증 패키지:\s*([^\n\r]+)",
                message
            ),

        "source_workstation":
            extract_field(
                r"원본 워크스테이션:\s*([^\n\r]+)",
                message
            ),

        "error_code":
            extract_field(
                r"오류 코드:\s*([^\n\r]+)",
                message
            )
    }

    return event


# =========================
# Event 4798
# Enumerate Local Group Membership
# =========================

def parse_event_4798(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "local_group_membership_enumeration"
    )

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]+)",
        message
    )

    event["process_path"] = process_path

    if process_path:

        event["process_name"] = os.path.basename(
            process_path
        ).lower()

    pid = extract_field(
        r"프로세스 ID:\s*(0x[a-fA-F0-9]+)",
        message
    )

    event["pid"] = safe_hex_to_int(pid)

    return event

# =========================
# Event 4799
# Enumerate Local Group Members
# =========================

def parse_event_4799(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "security_group_enumeration"
    )

    group_name = extract_field(
        r"그룹 이름:\s*([^\n\r]+)",
        message
    )

    process_path = extract_field(
        r"프로세스 이름:\s*([^\n\r]+)",
        message
    )

    pid = extract_field(
        r"프로세스 ID:\s*(0x[a-fA-F0-9]+)",
        message
    )

    event["pid"] = safe_hex_to_int(pid)

    event["process_path"] = process_path

    if process_path:

        event["process_name"] = os.path.basename(
            process_path
        ).lower()

        event["artifacts"].append(
            make_artifact(
                "process",
                process_path
            )
        )

    event["additional_fields"] = {

        "group_name":
            group_name,

        "group_domain":
            extract_field(
                r"그룹 도메인:\s*([^\n\r]+)",
                message
            )
    }

    return event

# =========================
# Event 5154
# Port Listen Allowed
# =========================

def parse_event_5154(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "port_listen_allowed"
    )

    process_path = extract_field(
        r"응용 프로그램 이름:\s*([^\n\r]+)",
        message
    )

    pid = extract_field(
        r"프로세스 ID:\s*([0-9]+)",
        message
    )

    event["pid"] = safe_int(pid)

    event["process_path"] = process_path

    if process_path:

        event["process_name"] = os.path.basename(
            process_path
        ).lower()

        event["artifacts"].append(
            make_artifact(
                "process",
                process_path
            )
        )

    source_ip = extract_field(
        r"원본 주소:\s*([^\n\r]+)",
        message
    )

    source_port = safe_int(
        extract_field(
            r"원본 포트:\s*([0-9]+)",
            message
        )
    )

    event["destination_ip"] = source_ip
    event["destination_port"] = source_port

    if source_ip:

        event["artifacts"].append(
            make_artifact(
                "ip",
                source_ip
            )
        )

    # 흔한 reverse shell / listener 포트 heuristic
    if source_port in [4444, 5555, 1337]:

        event["event_type"] = (
            "suspicious_listener"
        )

    event["additional_fields"] = {

        "protocol":
            extract_field(
                r"프로토콜:\s*([^\n\r]+)",
                message
            ),

        "layer_name":
            extract_field(
                r"계층 이름:\s*([^\n\r]+)",
                message
            )
    }

    return event

# =========================
# Event 5382
# Vault Credential Read
# =========================

def parse_event_5382(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "vault_credential_access"
    )

    subject_section = extract_field(
        r"주체:(.*)",
        message
    )

    if subject_section:

        account_name = extract_field(
            r"계정 이름:\s*([^\n\r]+)",
            subject_section
        )

        account_domain = extract_field(
            r"계정 도메인:\s*([^\n\r]+)",
            subject_section
        )

        if account_name and account_domain:

            event["user"] = (
                f"{account_domain}\\{account_name}"
            )

    return event

# =========================
# Event 6416
# External Device Connected
# =========================

def parse_event_6416(row):

    message = row["Message"]

    event = base_event(row)

    event["event_type"] = (
        "external_device_connected"
    )

    device_id = extract_field(
        r"장치 ID:\s*([^\n\r]+)",
        message
    )

    device_name = extract_field(
        r"장치 이름:\s*([^\n\r]+)",
        message
    )

    if device_id:

        event["artifacts"].append(
            make_artifact(
                "device",
                device_id
            )
        )

    # USB/Storage semantic 강화
    if device_id:

        lower_device = device_id.lower()

        if "usb" in lower_device:

            event["event_type"] = (
                "usb_device_connected"
            )

        elif "disk" in lower_device:

            event["event_type"] = (
                "storage_device_connected"
            )

    event["additional_fields"] = {

        "device_id":
            device_id,

        "device_name":
            device_name,

        "class_id":
            extract_field(
                r"클래스 ID:\s*([^\n\r]+)",
                message
            ),

        "class_name":
            extract_field(
                r"클래스 이름:\s*([^\n\r]+)",
                message
            ),

        "vendor_id":
            extract_field(
                r"공급업체 ID:\s*([^\n\r]+)",
                message
            ),

        "location":
            extract_field(
                r"위치 정보:\s*([^\n\r]+)",
                message
            )
    }

    return event

# =========================
# Event Routing
# =========================

EVENT_PARSERS = {

    4624: parse_event_4624,
    4625: parse_event_4625,
    4634: parse_event_4634,
    4648: parse_event_4648,

    4656: parse_event_4656,
    4657: parse_event_4657,
    4658: parse_event_4658,
    4659: parse_event_4659,
    4660: parse_event_4660,
    4663: parse_event_4663,

    4672: parse_event_4672,
    4673: parse_event_4673,
    4674: parse_event_4674,

    4688: parse_event_4688,
    4690: parse_event_4690,
    4698: parse_event_4698,
    4699: parse_event_4699,
    4702: parse_event_4702,

    4720: parse_event_4720,
    4722: parse_event_4722,
    4724: parse_event_4724,
    4726: parse_event_4726,
    4728: parse_event_4728,
    4729: parse_event_4729,
    4732: parse_event_4732,
    4733: parse_event_4733,
    4738: parse_event_4738,

    4776: parse_event_4776,
    4798: parse_event_4798,
    4799: parse_event_4799,

    4907: parse_event_4907,

    5154: parse_event_5154,
    5156: parse_event_5156,
    5158: parse_event_5158,

    5379: parse_event_5379,
    5382: parse_event_5382,
    6416: parse_event_6416
}


# =========================
# 메인
# =========================

def main():

    df = pd.read_csv(INPUT_FILE)

    # =========================
    # CSV는 최신→과거
    # 역순으로 뒤집어서
    # 정상 시간순으로 변환
    # =========================

    df = df.iloc[::-1].reset_index(drop=True)

    normalized_events = []

    parsed_count = 0
    skipped_count = 0
    error_count = 0

    for _, row in df.iterrows():

        try:

            event_id = int(row["Id"])

            if event_id not in EVENT_PARSERS:

                skipped_count += 1
                continue

            parser = EVENT_PARSERS[event_id]

            normalized = parser(row)

            normalized_events.append(
                normalized
            )

            parsed_count += 1

        except Exception as e:

            error_count += 1

            print(
                f"[ERROR] EventID={row.get('Id')} | {e}"
            )

    # =========================
    # 정렬 없음
    # CSV reverse 순서 그대로 사용
    # =========================

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            normalized_events,
            f,
            ensure_ascii=False,
            indent=2
        )

    print(f"[+] Saved: {OUTPUT_FILE}")
    print(f"[+] Parsed events: {parsed_count}")
    print(f"[+] Skipped events: {skipped_count}")
    print(f"[+] Error events: {error_count}")

# =========================
# 실행
# =========================

if __name__ == "__main__":

    main()