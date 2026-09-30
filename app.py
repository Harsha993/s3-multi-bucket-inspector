import streamlit as st
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
import configparser
import zipfile
import gzip
import io
import re
import os
import json

st.set_page_config(page_title="S3 Multi-Profile Inspector", layout="wide", page_icon="🛡️")

CONFIG_FILE = "profiles.json"
AWS_CREDENTIALS_FILE = os.path.expanduser("~/.aws/credentials")

# --- Helper: Read available AWS CLI profiles ---
def get_available_aws_profiles():
    profiles = ["default"]
    if os.path.exists(AWS_CREDENTIALS_FILE):
        config = configparser.ConfigParser()
        config.read(AWS_CREDENTIALS_FILE)
        profiles = list(config.sections())
        if "default" not in profiles:
            profiles.insert(0, "default")
    return profiles

# --- Helper: Local Preset Config Persistence ---
DEFAULT_CONFIG = {
    "default_preset": "Vodaplay Server Logs",
    "presets": {
        "Vodaplay Server Logs": {
            "aws_profile": "vodaplay",
            "bucket_name": "vodaplay-serverlogs",
            "base_prefix": "api-location/app_server",
            "fallback_region": "ap-southeast-2",
            "use_date_partitioning": True,
            "has_hourly_filenames": True
        }
    }
}

def load_presets():
    if not os.path.exists(CONFIG_FILE):
        save_presets(DEFAULT_CONFIG)
        return DEFAULT_CONFIG
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG

def save_presets(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=4)

config_data = load_presets()
available_aws_profiles = get_available_aws_profiles()

# --- Sidebar: Presets & Configurations ---
with st.sidebar:
    st.header("🗂️ S3 Profiles & Presets")
    
    preset_names = list(config_data.get("presets", {}).keys())
    default_preset = config_data.get("default_preset", "")
    default_idx = preset_names.index(default_preset) if default_preset in preset_names else 0

    selected_preset = st.selectbox("Active Preset", preset_names, index=default_idx)
    active_cfg = config_data["presets"].get(selected_preset, {})

    # Auto-populated fields based on active preset
    prof = active_cfg.get("aws_profile", "default")
    aws_prof_idx = available_aws_profiles.index(prof) if prof in available_aws_profiles else 0
    selected_aws_profile = st.selectbox("AWS CLI Profile", available_aws_profiles, index=aws_prof_idx)
    
    bucket_name = st.text_input("S3 Bucket Name", value=active_cfg.get("bucket_name", ""))
    base_prefix = st.text_input("Base Key Prefix", value=active_cfg.get("base_prefix", ""))
    fallback_region = st.text_input("Fallback / Client Region", value=active_cfg.get("fallback_region", "ap-southeast-2"))
    
    use_date_partitioning = st.checkbox("Partitioned by YYYY/MM/DD folders", value=active_cfg.get("use_date_partitioning", True))
    has_hourly_filenames = st.checkbox("Files have hourly timestamps (_HH.)", value=active_cfg.get("has_hourly_filenames", True))

    max_workers = st.slider("Concurrent Scan Threads", min_value=1, max_value=16, value=6)

    # --- Preset Management Expander ---
    with st.expander("🛠️ Manage / Save Presets"):
        new_preset_name = st.text_input("Preset Name to Save/Update", value=selected_preset)
        col_p1, col_p2 = st.columns(2)
        
        with col_p1:
            if st.button("💾 Save Preset"):
                if new_preset_name.strip():
                    config_data["presets"][new_preset_name.strip()] = {
                        "aws_profile": selected_aws_profile,
                        "bucket_name": bucket_name.strip(),
                        "base_prefix": base_prefix.strip(),
                        "fallback_region": fallback_region.strip(),
                        "use_date_partitioning": use_date_partitioning,
                        "has_hourly_filenames": has_hourly_filenames
                    }
                    save_presets(config_data)
                    st.success(f"Saved '{new_preset_name}'!")
                    st.rerun()

        with col_p2:
            if st.button("⭐ Set as Default"):
                config_data["default_preset"] = selected_preset
                save_presets(config_data)
                st.success(f"Default set to '{selected_preset}'!")

        if len(config_data["presets"]) > 1:
            if st.button("🗑️ Delete Selected Preset", type="secondary"):
                del config_data["presets"][selected_preset]
                config_data["default_preset"] = list(config_data["presets"].keys())[0]
                save_presets(config_data)
                st.warning(f"Deleted '{selected_preset}'.")
                st.rerun()

# --- Main UI Search Parameters ---
st.title("🔍 S3 Multi-Bucket Inspector")

# Date & Time Filters (Adaptive based on preset settings)
if use_date_partitioning:
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", datetime(2026, 8, 1))
    with col2:
        end_date = st.date_input("End Date", datetime(2026, 8, 13))
else:
    st.info("ℹ️ Flat mode active: scanning prefix directly without date subdirectories.")
    start_date, end_date = None, None

if has_hourly_filenames:
    hour_range = st.slider("⏰ Hour Range Filter", min_value=0, max_value=23, value=(0, 23), format="%02d:00")
else:
    hour_range = None

col_search, col_opts = st.columns([3, 2])
with col_search:
    search_term = st.text_input("Search Term / Unique ID / Pattern", placeholder="e.g. D145B2C09B227BCBDF or image_id_102")
with col_opts:
    st.write("Match Options")
    co1, co2 = st.columns(2)
    with co1:
        use_regex = st.checkbox("Regex Mode", value=False)
    with co2:
        case_sensitive = st.checkbox("Case Sensitive", value=False)

col_ctx1, col_ctx2 = st.columns(2)
with col_ctx1:
    context_lines = st.slider("Context Lines (Before & After match)", min_value=0, max_value=10, value=2)
with col_ctx2:
    max_display_matches = st.slider("Max Match Occurrences per File", min_value=1, max_value=50, value=15)


# --- Helper Logic ---
def get_session():
    # 1. If running on Streamlit Community Cloud (Secrets configured)
    if "aws" in st.secrets:
        return boto3.Session(
            aws_access_key_id=st.secrets["aws"]["aws_access_key_id"],
            aws_secret_access_key=st.secrets["aws"]["aws_secret_access_key"],
            region_name=st.secrets["aws"].get("region_name", "ap-southeast-2"),
        )
    # 2. If running locally with ~/.aws/credentials
    if selected_aws_profile and selected_aws_profile != "default":
        return boto3.Session(profile_name=selected_aws_profile)
    return boto3.Session()

def resolve_bucket_region(session, bucket, fallback):
    try:
        s3_client = session.client("s3", region_name=fallback)
        loc = s3_client.get_bucket_location(Bucket=bucket).get("LocationConstraint")
        if not loc:
            return "us-east-1"
        if loc == "EU":
            return "eu-west-1"
        return loc
    except Exception:
        return fallback

def generate_date_prefixes(start, end, base):
    if not start or not end:
        return [f"{base.rstrip('/')}/"] if base else [""]
    prefixes = []
    curr = start
    while curr <= end:
        prefix = f"{base.rstrip('/')}/{curr.strftime('%Y/%m/%d')}/" if base else f"{curr.strftime('%Y/%m/%d')}/"
        prefixes.append(prefix)
        curr += timedelta(days=1)
    return prefixes

def is_within_hour_range(key_name, hr_range):
    if not hr_range:
        return True
    min_hr, max_hr = hr_range
    match = re.search(r"[_T](\d{2})[\.\-_]", key_name)
    if match:
        file_hour = int(match.group(1))
        return min_hr <= file_hour <= max_hr
    return True

def compile_pattern(query, regex_mode, is_case_sensitive):
    flags = 0 if is_case_sensitive else re.IGNORECASE
    return re.compile(query, flags) if regex_mode else re.compile(re.escape(query), flags)

def inspect_s3_file(bucket, key, pattern, context_size, max_matches, session, config):
    s3 = session.client("s3", config=config)
    match_blocks = []
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        raw_bytes = response["Body"].read()
        file_streams = []

        if key.endswith(".zip"):
            zf = zipfile.ZipFile(io.BytesIO(raw_bytes), "r")
            for member_name in zf.namelist():
                file_streams.append((member_name, zf.open(member_name, "r")))
        elif key.endswith(".gz"):
            gf = gzip.GzipFile(fileobj=io.BytesIO(raw_bytes), mode="rb")
            file_streams.append((key.split("/")[-1].replace(".gz", ""), gf))
        else:
            file_streams.append((key.split("/")[-1], io.BytesIO(raw_bytes)))

        for member_name, stream in file_streams:
            line_window = deque(maxlen=context_size)
            lines_after_needed = 0
            current_block = []
            line_no = 0

            for raw_line in stream:
                line_no += 1
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")

                if pattern.search(line):
                    block_lines = []
                    for prev_no, prev_line in line_window:
                        block_lines.append(f"   {prev_no:5d} | {prev_line}")
                    block_lines.append(f">> {line_no:5d} | {line}")
                    current_block = block_lines
                    lines_after_needed = context_size
                elif lines_after_needed > 0:
                    current_block.append(f"   {line_no:5d} | {line}")
                    lines_after_needed -= 1
                    if lines_after_needed == 0:
                        match_blocks.append((member_name, current_block))
                        if len(match_blocks) >= max_matches:
                            break

                line_window.append((line_no, line))

            if lines_after_needed > 0 and current_block:
                match_blocks.append((member_name, current_block))

            if len(match_blocks) >= max_matches:
                break

        return {"key": key, "matches": match_blocks, "error": None}
    except Exception as e:
        return {"key": key, "matches": [], "error": str(e)}

def extract_inner_file(bucket, key, session, config):
    s3 = session.client("s3", config=config)
    raw_data = s3.get_object(Bucket=bucket, Key=key)["Body"].read()

    if key.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(raw_data), "r") as zf:
            for name in zf.namelist():
                if name.endswith(".log") or name.endswith(".txt") or not name.endswith(".zip"):
                    return name, zf.read(name)
    elif key.endswith(".gz"):
        uncompressed = gzip.decompress(raw_data)
        return key.split("/")[-1].replace(".gz", ""), uncompressed

    return key.split("/")[-1], raw_data


# --- Execution ---
if st.button("🚀 Start Search", type="primary"):
    if not search_term.strip():
        st.warning("Please enter a search term.")
        st.stop()

    if use_date_partitioning and start_date > end_date:
        st.error("Start Date cannot be later than End Date.")
        st.stop()

    try:
        compiled_pattern = compile_pattern(search_term, use_regex, case_sensitive)
    except re.error as re_err:
        st.error(f"Invalid Regular Expression: {re_err}")
        st.stop()

    try:
        session = get_session()
        bucket_region = resolve_bucket_region(session, bucket_name, fallback_region)
        config = Config(
            region_name=bucket_region,
            signature_version="s3v4",
            retries={"max_attempts": 3, "mode": "standard"},
            connect_timeout=10,
            read_timeout=60
        )
        s3 = session.client("s3", config=config)
        s3.head_bucket(Bucket=bucket_name)
    except Exception as e:
        st.error(f"Failed to connect to AWS: {e}")
        st.stop()

    search_prefixes = generate_date_prefixes(start_date, end_date, base_prefix) if use_date_partitioning else [base_prefix.strip()]
    status_text = st.empty()
    status_text.info(f"Connected using AWS Profile: `{selected_aws_profile}` in `{bucket_region}`. Listing keys...")

    target_keys = []
    skipped_by_hour = 0

    for prefix in search_prefixes:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
            for obj in page.get("Contents", []):
                k = obj["Key"]
                if is_within_hour_range(k, hour_range):
                    target_keys.append(k)
                else:
                    skipped_by_hour += 1

    total_files = len(target_keys)
    if total_files == 0:
        status_text.warning("No files found matching the criteria.")
        st.stop()

    status_text.info(f"Scanning {total_files} file(s)... (skipped {skipped_by_hour} out of hour bounds)")
    progress_bar = st.progress(0)
    matched_count = 0
    scanned_count = 0
    results_container = st.container()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                inspect_s3_file,
                bucket_name,
                key,
                compiled_pattern,
                context_lines,
                max_display_matches,
                session,
                config
            ): key for key in target_keys
        }

        for future in as_completed(future_map):
            scanned_count += 1
            progress_bar.progress(scanned_count / total_files)

            res = future.result()
            if res["error"]:
                st.caption(f"⚠️ Error scanning `{res['key']}`: {res['error']}")
                continue

            if res["matches"]:
                matched_count += 1
                key = res["key"]
                matches = res["matches"]
                file_name = key.split("/")[-1]

                with results_container.expander(f"📄 **{key}** ({len(matches)} match incident/s)", expanded=True):
                    btn_col1, btn_col2 = st.columns([1, 1])

                    with btn_col1:
                        try:
                            download_url = s3.generate_presigned_url(
                                "get_object",
                                Params={"Bucket": bucket_name, "Key": key},
                                ExpiresIn=900
                            )
                            st.link_button(f"⬇️ Download Raw Object ({file_name})", download_url)
                        except Exception as err:
                            st.caption(f"Error creating link: {err}")

                    with btn_col2:
                        try:
                            inner_name, log_bytes = extract_inner_file(bucket_name, key, session, config)
                            st.download_button(
                                label=f"📂 Extract & Download Text ({inner_name})",
                                data=log_bytes,
                                file_name=inner_name,
                                mime="text/plain",
                                key=f"dl_extracted_{key}"
                            )
                        except Exception as err:
                            st.caption(f"Could not extract file: {err}")

                    for idx, (member_name, block) in enumerate(matches, 1):
                        st.caption(f"**Match #{idx}** from member: `{member_name}`")
                        st.code("\n".join(block), language="log")

    progress_bar.empty()
    status_text.success(f"Finished! Scanned **{total_files}** files. Found matches in **{matched_count}** file(s).")
