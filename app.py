import os
import requests
import jwt
import logging
import json
import pandas as pd
import streamlit as st

# Setup logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

def get_env_or_input(env_name, prompt_text, default_value=None):
    value = os.getenv(env_name)
    if value:
        logger.info(f"{env_name} loaded from environment.")
        return value
    else:
        user_input = input(f"{prompt_text} (default: {default_value}): ").strip()
        return user_input or default_value

def extract_env_variables(response_json, keys):
    env_data = {}
    for key in keys:
        value = response_json.get("data", {}).get(key)
        if value:
            env_data[key] = value
    return env_data

def main():
    st.title("LXME API Testing")

    # Input section for parameters
    mobile_number = st.text_input("📱 Enter Mobile Number")
    otp = st.text_input("🔢 Enter OTP")
    secret_key = st.text_input("🔑 Enter Secret Key for JWT", "bfksjfojsafhiyasfjkasdblksb")

    url_v2 = st.text_input('URL_V2', 'https://tmp-stage.lxme.in')
    url = st.text_input('URL', 'https://api-stagev1.lxme.in')

    send_otp_url = f"{url_v2}/gin-v2/send-otp"
    verify_otp_url = f"{url_v2}/gin-v2/verify-otp"
    user_detail_url = f"{url}/public/auth/v2/get-user-detail"

    # Ask the user to upload the api.json file
    postman_file = st.file_uploader("📂 Upload api.json (Postman Collection) File", type=["json"])

    collection = None  # Variable to store Postman collection
    if postman_file is not None:
        try:
            collection = json.load(postman_file)  # Load JSON content from the uploaded file
            logger.info(f"✅ Postman collection loaded successfully.")
        except json.JSONDecodeError as e:
            st.error(f"❌ Failed to parse uploaded file as JSON: {e}")
            logger.error(f"❌ Failed to parse uploaded file as JSON: {e}")
            return

    if st.button("Start API Flow"):
        logger.info("🚀 Starting API Flow for LXME...")

        # Step 1: Send OTP
        logger.info("📤 Sending OTP...")
        send_otp_payload = {"mobile_number": mobile_number, "hash_key": "jhjh"}
        send_otp_response = requests.post(send_otp_url, json=send_otp_payload)

        # Check if the response content type is JSON before calling json()
        if send_otp_response.headers.get('Content-Type') == 'application/json':
            try:
                send_otp_data = send_otp_response.json()
                logger.info(f"✅ Send OTP Response: {send_otp_data}")
            except ValueError as e:
                logger.error(f"❌ Error parsing Send OTP response as JSON: {e}")
        else:
            logger.warning(f"⚠️ Send OTP Response is not JSON: {send_otp_response.text}")

        # Step 2: Verify OTP
        logger.info("🔎 Verifying OTP...")
        verify_otp_payload = {"mobile_number": mobile_number, "hash_key": "jhjh", "otp": otp}
        verify_otp_response = requests.post(verify_otp_url, json=verify_otp_payload)

        # Check if response content is empty
        if not verify_otp_response.text.strip():
            st.error("❌ OTP Verification response is empty. Please check the server or request parameters.")
            logger.error("❌ OTP Verification response is empty.")
            return

        try:
            verify_otp_data = verify_otp_response.json()
        except ValueError as e:
            st.error(f"❌ Failed to parse OTP verification response: {e}")
            logger.error(f"❌ Failed to parse OTP verification response: {e}")
            logger.debug(f"Raw response text: {verify_otp_response.text}")
            return

        if verify_otp_response.status_code == 200 and "data" in verify_otp_data and "access_token" in verify_otp_data["data"]:
            access_token = verify_otp_data["data"]["access_token"]
            refresh_token = verify_otp_data["data"]["refresh_token"]
            cookies = requests.utils.dict_from_cookiejar(verify_otp_response.cookies)

            # Optional: Extract environment variables like party_id, user_id
            env_vars = extract_env_variables(verify_otp_data, ["party_id", "user_id"])

            # Step 3: Decode JWT safely
            decoded = None
            try:
                decoded = jwt.decode(access_token, secret_key, algorithms=["HS256"])
                logger.info(f"✅ Decoded JWT Payload: {decoded}")
            except Exception as e:
                logger.error(f"❌ JWT Decode Error: {e}")
                decoded = {}  # Fallback to an empty dictionary if decoding fails

            # Step 4: Save full session data
            session_data = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "cookies": cookies,
                "decoded_jwt": decoded,
                "full_verify_otp_response": verify_otp_data
            }
            with open("session.json", "w") as f:
                json.dump(session_data, f, indent=2)
            logger.info("💾 Session data saved to session.json")
            
            # Step 5: Fetch user detail
            headers = {"token": access_token}
            user_detail_payload = {
                "access_token": access_token,
                "refresh_token": refresh_token
            }
            user_detail_response = requests.post(user_detail_url, json=user_detail_payload, headers=headers)

            if user_detail_response.status_code == 200:
                logger.info(f"✅ User Detail Response: {user_detail_response.json()}")
                # Save user detail response
                with open("user_detail_response.json", "w") as f:
                    json.dump(user_detail_response.json(), f, indent=2)
                st.success("User detail fetched successfully and saved.")
            else:
                st.error(f"Error fetching user details: {user_detail_response.text}")
                logger.error(f"❌ Error fetching user details: {user_detail_response.text}")

            # Step 6: Test downstream APIs and collect results if the Postman file was uploaded
            if collection:
                logger.info("📊 Running downstream API tests based on Postman collection...")

                # Step 7: Test downstream APIs and collect results
                base_url = url
                results = []

                def run_request(name, request, url, url_v2, access_token, cookies):
                    method = request.get("method", "GET")
                    raw_url = request.get("url", {}).get("raw", "")
                    headers = {h["key"]: h["value"] for h in request.get("header", [])}

                    # Replace placeholders
                    raw_url = raw_url.replace("{{url}}", url).replace("{{url_v2}}", url_v2).replace("{{access_token}}", access_token)
                    headers = {k: v.replace("{{access_token}}", access_token) for k, v in headers.items()}

                    body = None
                    if request.get("body", {}).get("mode") == "raw":
                        body = request["body"]["raw"]

                    try:
                        logger.info(f"➡️ {method} {raw_url}")
                        resp = requests.request(method, raw_url, headers=headers, data=body, cookies=cookies)
                        result = {
                            "API Name": name,
                            "Method": method,
                            "URL": raw_url,
                            "Status Code": resp.status_code,
                            "Status Text": resp.reason,
                            "Response (truncated)": resp.text[:300]
                        }
                    except Exception as e:
                        result = {
                            "API Name": name,
                            "Method": method,
                            "URL": raw_url,
                            "Status Code": "ERROR",
                            "Status Text": str(e),
                            "Response (truncated)": ""
                        }

                    return result


                for item in collection.get("item", []):
                    if "request" in item:
                        results.append(run_request(item.get("name", "Unnamed"), item["request"], url, url_v2, access_token, cookies))
                    elif "item" in item:  # folder
                        for subitem in item["item"]:
                            if "request" in subitem:
                                results.append(run_request(subitem.get("name", "Unnamed"), subitem["request"], url, url_v2, access_token, cookies))
            # Step 8: Export session.json for download
            with open("session.json", "r") as f:
                session_data_content = f.read()

            st.download_button(
                label="Download Session.json",
                data=session_data_content,
                file_name="session.json",
                mime="application/json"
            )
            
            # Step 9: Export results to Excel
            df = pd.DataFrame(results)

            # Write Excel to a BytesIO object instead of saving to disk
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine="xlsxwriter") as writer:
                df.to_excel(writer, index=False, sheet_name="Results")
                writer.save()

            # Move buffer to the beginning
            excel_buffer.seek(0)

            # Download button for Excel
            st.download_button(
                label="📥 Download API Results (Excel)",
                data=excel_buffer,
                file_name="downstream_api_results.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

            # Log and Streamlit success message
            logger.info("📊 API test results exported to downstream_api_results.xlsx")
            st.success("✅ API test results exported successfully.")
        else:
            logger.error(f"❌ OTP Verification Failed: {verify_otp_data}")
            st.error(f"OTP Verification failed. Response: {verify_otp_data}")

    logger.info("🎉 Downstream API testing completed successfully!")

if __name__ == "__main__":
    main()