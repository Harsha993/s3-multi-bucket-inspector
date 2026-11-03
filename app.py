import streamlit as st
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
import threading
import configparser
import zipfile
import gzip
import io
import re
import os
import json

st.set_page_config(page_title="S3 Log Inspector", layout="wide", page_icon="🛡️")

CONFIG_FILE = "profiles.json"
AWS_CREDENTIALS_FILE = os.path.expanduser("~/.aws/credentials")

# --- Helper: Safe Secrets Detector ---
def get_cloud_aws_credentials():
    """Safely extracts Streamlit secrets without crashing if no secrets.toml exists."""
    try:
        if bool(st.secrets) and "aws" in st.secrets:
            return st.secrets["aws"]
    except BaseException:
        pass
    return None

cloud_aws_creds = get_cloud_aws_credentials()
has_cloud_secrets = cloud_aws_creds is not None
has_local_creds = os.path.exists(AWS_CREDENTIALS_FILE)

# --- Helper: Read available AWS CLI profiles ---
def get_available_aws_profiles():
    profiles = []
    if os.path.exists(AWS_CREDENTIALS_FILE):
        config = configparser.ConfigParser()
        config.read(AWS_CREDENTIALS_FILE)
        profiles = list(config.sections())
    if "default" not in profiles:
        profiles.insert(0, "default")
    return profiles

# --- Helper: Clean Default Presets ---
DEFAULT_CONFIG = {
    "default_preset": "Default Environment",
    "presets": {
        "Default Environment": {
            "aws_profile": "default",
            "bucket_name": "",
            "base_prefix": "",
            "fallback_region": "ap-southeast-2",
            "use_date_partitioning": True,
            "has_hourly_filenames": False
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
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception:
        pass

config_data = load_presets()
available_aws_profiles = get_available_aws_profiles()

# Initialize session state for persistent results across reruns
if "search_results" not in st.session_state:
    st.session_state.search_results = None
if "search_meta" not in st.session_state:
    st.session_state.search_meta = None

# --- Sidebar: Presets & Configurations ---
with st.sidebar:
    st.header("🗂️ S3 Profiles & Presets")
    
    preset_names = list(config_data.get("presets", {}).keys())
    default_preset = config_data.get("default_preset", "")
    default_idx = preset_names.index(default_preset) if default_preset in preset_names else 0

    def on_preset_change():
        chosen_preset = st.session_state.selected_preset_key
        p_cfg = config_data["presets"].get(chosen_preset, {})
        st.session_state.current_aws_profile = p_cfg.get("aws_profile", "default")
        st.session_state.current_bucket = p_cfg.get("bucket_name", "")
        st.session_state.current_prefix = p_cfg.get("base_prefix", "")
        st.session_state.current_region = p_cfg.get("fallback_region", "ap-southeast-2")
        st.session_state.current_date_part = p_cfg.get("use_date_partitioning", True)
        st.session_state.current_hourly = p_cfg.get("has_hourly_filenames", False)

    selected_preset = st.selectbox(
        "Active Preset",
        preset_names,
        index=default_idx,
        key="selected_preset_key",
        on_change=on_preset_change
    )

    if "current_aws_profile" not in st.session_state:
        init_cfg = config_data["presets"].get(selected_preset, {})
        st.session_state.current_aws_profile = init_cfg.get("aws_profile", "default")
        st.session_state.current_bucket = init_cfg.get("bucket_name", "")
        st.session_state.current_prefix = init_cfg.get("base_prefix", "")
        st.session_state.current_region = init_cfg.get("fallback_region", "ap-southeast-2")
        st.session_state.current_date_part = init_cfg.get("use_date_partitioning", True)
        st.session_state.current_hourly = init_cfg.get("has_hourly_filenames", False)

    cur_prof = st.session_state.current_aws_profile
    prof_idx = available_aws_profiles.index(cur_prof) if cur_prof in available_aws_profiles else 0
    
    def on_profile_change():
        new_prof = st.session_state.selected_profile_key
        st.session_state.current_aws_profile = new_prof
        matched = False
        for p_name, p_val in config_data.get("presets", {}).items():
            if p_val.get("aws_profile") == new_prof:
                st.session_state.current_bucket = p_val.get("bucket_name", "")
                st.session_state.current_prefix = p_val.get("base_prefix", "")
                st.session_state.current_region = p_val.get("fallback_region", "ap-southeast-2")
                st.session_state.current_date_part = p_val.get("use_date_partitioning", True)
                st.session_state.current_hourly = p_val.get("has_hourly_filenames", False)
                matched = True
                break
        if not matched:
            st.session_state.current_bucket = ""
            st.session_state.current_prefix = ""

    selected_aws_profile = st.selectbox(
        "AWS CLI Profile",
        available_aws_profiles,
        index=prof_idx,
        key="selected_profile_key",
        on_change=on_profile_change
    )

    manual_access_key = ""
    manual_secret_key = ""
    if not has_cloud_secrets and not has_local_creds:
        st.warning("⚠️ No AWS credentials detected on disk or in secrets.")
        with st.expander("🔑 Provide AWS Credentials", expanded=True):
            manual_access_key = st.text_input("Access Key ID", type="password")
            manual_secret_key = st.text_input("Secret Access Key", type="password")

    def get_session():
        if has_cloud_secrets:
            try:
                return boto3.Session(
                    aws_access_key_id=cloud_aws_creds["aws_access_key_id"],
                    aws_secret_access_key=cloud_aws_creds["aws_secret_access_key"],
                    region_name=cloud_aws_creds.get("region_name", "ap-southeast-2")
                )
            except Exception:
                pass
        if manual_access_key.strip() and manual_secret_key.strip():
            return boto3.Session(
                aws_access_key_id=manual_access_key.strip(),
                aws_secret_access_key=manual_secret_key.strip(),
                region_name=st.session_state.current_region
            )
        if has_local_creds and selected_aws_profile:
            try:
                s = boto3.Session(profile_name=selected_aws_profile)
                if s.get_credentials():
                    return s
            except Exception:
                pass
        return None

    @st.cache_data(ttl=300)
    def list_s3_buckets(_session):
        if not _session:
            return []
        try:
            s3 = _session.client("s3")
            response = s3.list_buckets()
            return [b["Name"] for b in response.get("Buckets", [])]
        except Exception:
            return []

    active_session = get_session()
    discovered_buckets = list_s3_buckets(active_session) if active_session else []

    st.write("**Target S3 Bucket**")
    if discovered_buckets:
        curr_b = st.session_state.current_bucket
        b_idx = discovered_buckets.index(curr_b) if curr_b in discovered_buckets else 0
        bucket_select_mode = st.radio("Bucket Input Mode", ["Choose from List", "Type Manually"], horizontal=True)
        if bucket_select_mode == "Choose from List":
            bucket_name = st.selectbox("Select Bucket", discovered_buckets, index=b_idx)
            st.session_state.current_bucket = bucket_name
        else:
            bucket_name = st.text_input("Bucket Name", value=st.session_state.current_bucket, placeholder="e.g. my-app-logs")
            st.session_state.current_bucket = bucket_name
    else:
        bucket_name = st.text_input("Bucket Name", value=st.session_state.current_bucket, placeholder="e.g. my-app-logs")
        st.session_state.current_bucket = bucket_name

    base_prefix = st.text_input("Base Key Prefix", value=st.session_state.current_prefix, placeholder="e.g. logs/production")
    st.session_state.current_prefix = base_prefix
    
    fallback_region = st.text_input("Fallback / Client Region", value=st.session_state.current_region)
    st.session_state.current_region = fallback_region
    
    use_date_partitioning = st.checkbox("Partitioned by YYYY/MM/DD folders", value=st.session_state.current_date_part)
    st.session_state.current_date_part = use_date_partitioning
    
    has_hourly_filenames = st.checkbox("Files have hourly timestamps (_HH.)", value=st.session_state.current_hourly)
    st.session_state.current_hourly = has_hourly_filenames

    max_workers = st.slider("Concurrent Scan Threads", min_value=1, max_value=32, value=12)

    # Preset Manager
    with st.expander("🛠️ Manage / Save Presets"):
        new_preset_name = st.text_input("Preset Name", value=selected_preset)
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

    st.markdown("---")
    st.caption("📬 **Support / Contact:**")
    st.markdown("[harshas@yupptv.com](mailto:harshas@yupptv.com)")

# --- Main UI Search Parameters ---
st.title("🔍 S3 Multi-Bucket Inspector")
st.caption("Maintained by **Harsha** • Contact: [harshas@yupptv.com](mailto:harshas@yupptv.com)")

# Date & Time Filters
if use_date_partitioning:
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", datetime.now() - timedelta(days=7))
    with col2:
        end_date = st.date_input("End Date", datetime.now())
else:
    st.info("ℹ️ Flat mode active: scanning prefix directly without date subdirectories.")
    start_date, end_date = None, None

if has_hourly_filenames:
    hour_range = st.slider("⏰ Hour Range Filter", min_value=0, max_value=23, value=(0, 23), format="%02d:00")
else:
    hour_range = None

col_search, col_opts = st.columns([3, 2])
with col_search:
    search_term = st.text_input("Search Term / Unique ID / Pattern", placeholder="e.g. D145B2C09B227BCBDF or (ERROR|WARN).+timeout")
with col_opts:
    st.write("Match Options")
    co1, co2, co3 = st.columns(3)
    with co1:
        use_regex = st.checkbox("Regex Mode", value=False)
    with co2:
        case_sensitive = st.checkbox("Case Sensitive", value=False)
    with co3:
        stop_on_first = st.checkbox("Stop on 1st Match", value=False, help="Stops scanning all remaining files as soon as 1 matching file is found.")

# Regex User Guide & Cheatsheet
with st.expander("💡 How to use Regex Mode (Instructions & Examples)", expanded=False):
    st.markdown("""
    When **Regex Mode** is checked, you can search for advanced patterns rather than exact literal text.
    
    ### 📌 Common Pattern Examples
    | Use Case | Example Query | What it matches |
    | :--- | :--- | :--- |
    | **Unique ID + Error only** | `D145B2C09B227BCBDF.*(ERROR\|Exception)` | Lines with this ID that *also* contain an error or exception. |
    | **Multiple IDs (OR search)** | `(ORD_101\|ORD_102\|ORD_103)` | Lines containing *any* of these three order numbers. |
    | **HTTP 5xx Server Errors** | `HTTP/1\.[01]"\s+50[0-5]` | HTTP status codes 500, 502, 503, 504, 505 in access logs. |
    | **Standard UUIDs** | `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}` | Any 36-character UUID/GUID request ID. |
    | **High Latency / Slow Queries** | `(took\|latency)[=:\s]+[1-9]\d{3,}\s*ms` | Execution times of 1,000 ms (1 sec) or greater. |
    | **Database Deadlocks / Pool** | `(Deadlock\|ConnectionPoolTimeout\|Too many connections)` | Database exhaustion or lock errors. |

    ### 🔤 Syntax Quick-Reference
    * `.*` : Matches any character sequence (e.g. `order.*failed`).
    * `(A|B)` : Matches either **A** OR **B** (e.g. `(ERROR|FATAL)`).
    * `\d+` : Matches one or more numbers (e.g. `user_\d+`).
    * `^` and `$` : Start and end of line (e.g. `^FATAL`).
    * `\` : Escape special characters (e.g. `\[ERROR\]` for literal brackets).
    """)

col_ctx1, col_ctx2 = st.columns(2)
with col_ctx1:
    context_lines = st.slider("Context Lines (Before & After match)", min_value=0, max_value=10, value=2)
with col_ctx2:
    max_display_matches = st.slider("Max Match Occurrences per File", min_value=1, max_value=50, value=15)


# --- Helper Logic ---
def resolve_bucket_region(session, bucket, fallback):
    try:
        s3_client = session.client("s3", region_name=fallback)
        loc = s3_client.get_bucket_location(Bucket=bucket).get("LocationConstraint")
        if not loc:
            return fallback
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

# --- Optimized Worker with stop_event check ---
def inspect_s3_file(bucket, key, pattern, context_size, max_matches, session, config, stop_event=None):
    # Short-circuit: if another thread already found a match and stop requested, exit immediately
    if stop_event and stop_event.is_set():
        return {"key": key, "matches": [], "error": None, "skipped": True}

    s3 = session.client("s3", config=config)
    match_blocks = []
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        body = response["Body"]
        file_streams = []

        if key.endswith(".gz"):
            file_streams.append((key.split("/")[-1].replace(".gz", ""), gzip.GzipFile(fileobj=body)))
        elif key.endswith(".zip"):
            raw_bytes = body.read()
            zf = zipfile.ZipFile(io.BytesIO(raw_bytes), "r")
            for member_name in zf.namelist():
                file_streams.append((member_name, zf.open(member_name, "r")))
        else:
            file_streams.append((key.split("/")[-1], body))

        for member_name, stream in file_streams:
            if stop_event and stop_event.is_set():
                break

            line_window = deque(maxlen=context_size)
            lines_after_needed = 0
            current_block = []
            line_no = 0

            for raw_line in stream:
                if stop_event and stop_event.is_set():
                    break

                line_no += 1
                try:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                except Exception:
                    continue

                if pattern.search(line):
                    block_lines = [f"   {prev_no:5d} | {prev_line}" for prev_no, prev_line in line_window]
                    block_lines.append(f">> {line_no:5d} | {line}")
                    current_block = block_lines
                    lines_after_needed = context_size
                elif lines_after_needed > 0:
                    current_block.append(f"   {line_no:5d} | {line}")
                    lines_after_needed -= 1
                    if lines_after_needed == 0:
                        match_blocks.append((member_name, current_block))
                        if len(match_blocks) >= max_matches:
                            return {"key": key, "matches": match_blocks, "error": None, "skipped": False}

                line_window.append((line_no, line))

            if lines_after_needed > 0 and current_block:
                match_blocks.append((member_name, current_block))

            if len(match_blocks) >= max_matches:
                return {"key": key, "matches": match_blocks, "error": None, "skipped": False}

        return {"key": key, "matches": match_blocks, "error": None, "skipped": False}
    except Exception as e:
        return {"key": key, "matches": [], "error": str(e), "skipped": False}

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


# --- Search Execution Trigger ---
if st.button("🚀 Start Search", type="primary"):
    if not search_term.strip():
        st.warning("Please enter a search term.")
        st.stop()

    if not bucket_name.strip():
        st.error("Please enter or select a bucket name.")
        st.stop()

    if use_date_partitioning and start_date > end_date:
        st.error("Start Date cannot be later than End Date.")
        st.stop()

    session = get_session()
    if session is None:
        st.error("❌ Authentication Error: No valid AWS credentials found. Please provide keys in the sidebar or configure AWS CLI.")
        st.stop()

    try:
        compiled_pattern = compile_pattern(search_term, use_regex, case_sensitive)
    except re.error as re_err:
        st.error(f"Invalid Regular Expression: {re_err}")
        st.stop()

    try:
        bucket_region = resolve_bucket_region(session, bucket_name, fallback_region)
        config = Config(
            region_name=bucket_region,
            signature_version="s3v4",
            max_pool_connections=max_workers + 6,
            retries={"max_attempts": 2, "mode": "standard"},
            connect_timeout=6,
            read_timeout=45
        )
        s3 = session.client("s3", config=config)
        s3.head_bucket(Bucket=bucket_name)
    except Exception as e:
        st.error(f"Failed to connect to AWS bucket '{bucket_name}': {e}")
        st.stop()

    search_prefixes = generate_date_prefixes(start_date, end_date, base_prefix) if use_date_partitioning else [base_prefix.strip()]
    status_text = st.empty()
    status_text.info(f"Targeting region `{bucket_region}`. Listing keys...")

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
        st.session_state.search_results = []
        st.session_state.search_meta = None
        st.stop()

    mode_label = " (Stop on 1st match enabled)" if stop_on_first else ""
    status_text.info(f"Scanning {total_files} file(s) across {max_workers} threads{mode_label}... (skipped {skipped_by_hour} out of hour bounds)")
    progress_bar = st.progress(0)
    scanned_count = 0
    collected_results = []
    
    stop_event = threading.Event()

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
                config,
                stop_event
            ): key for key in target_keys
        }

        for future in as_completed(future_map):
            scanned_count += 1
            progress_bar.progress(min(scanned_count / total_files, 1.0))

            res = future.result()
            if not res.get("skipped", False) and not res["error"] and res["matches"]:
                collected_results.append(res)
                
                # If short-circuit option is turned on, cancel all other tasks immediately!
                if stop_on_first:
                    stop_event.set()
                    for f in future_map:
                        f.cancel()
                    break

    progress_bar.empty()
    status_text.empty()

    # Store in session state so subsequent clicks (e.g. downloads) won't wipe results
    st.session_state.search_results = collected_results
    st.session_state.search_meta = {
        "total_scanned": scanned_count,
        "total_available": total_files,
        "matched_count": len(collected_results),
        "bucket": bucket_name,
        "region": bucket_region,
        "stopped_early": stop_on_first and len(collected_results) > 0
    }


# --- Persistent Results Rendering ---
if st.session_state.search_results is not None:
    meta = st.session_state.search_meta
    if meta:
        if meta.get("stopped_early"):
            st.success(f"🎯 **Found 1st match!** Stopped remaining scans after inspecting **{meta['total_scanned']} / {meta['total_available']}** files.")
        else:
            st.success(f"Finished! Scanned **{meta['total_scanned']}** files. Found matches in **{meta['matched_count']}** file(s).")

        session = get_session()
        if session:
            config = Config(
                region_name=meta["region"],
                signature_version="s3v4",
                retries={"max_attempts": 2, "mode": "standard"},
                connect_timeout=6,
                read_timeout=45
            )
            s3 = session.client("s3", config=config)

            for res in st.session_state.search_results:
                key = res["key"]
                matches = res["matches"]
                file_name = key.split("/")[-1]

                with st.expander(f"📄 **{key}** ({len(matches)} match incident/s)", expanded=True):
                    btn_col1, btn_col2 = st.columns([1, 1])

                    with btn_col1:
                        try:
                            download_url = s3.generate_presigned_url(
                                "get_object",
                                Params={"Bucket": meta["bucket"], "Key": key},
                                ExpiresIn=900
                            )
                            st.link_button(f"⬇️ Download Raw Archive ({file_name})", download_url)
                        except Exception as err:
                            st.caption(f"Error creating link: {err}")

                    with btn_col2:
                        try:
                            inner_name, log_bytes = extract_inner_file(meta["bucket"], key, session, config)
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
