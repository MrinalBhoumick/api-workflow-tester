### 🔍 **Test the API authentication flow and validate downstream APIs** using a Postman collection.
It automates the following steps:
---

## 💡 **Key Features:**

### 1. **User Inputs via Streamlit UI**
- `📱 Mobile Number` and `🔢 OTP` for authentication.
- `🔑 Secret Key` for decoding the JWT.
- `URL_V2` and `URL` base URLs.
- Option to upload a **Postman collection JSON file** (`api.json`).

---

### 2. **API Authentication Flow**
The script executes the following in order:

#### ✅ **Step 1: Send OTP**
- Sends an OTP to the mobile number using the endpoint `/gin-v2/send-otp`.

#### ✅ **Step 2: Verify OTP**
- Submits the OTP using `/gin-v2/verify-otp`.
- On success, extracts:
  - `access_token` and `refresh_token`
  - Optional environment variables like `party_id`, `user_id`
  - Decodes the JWT using the secret key provided by the user

#### ✅ **Step 3: Save Session**
- Saves the full session (`access_token`, `refresh_token`, `cookies`, JWT payload) to `session.json`.

#### ✅ **Step 4: Get User Details**
- Calls `get-user-detail` endpoint using the access token to fetch user details and saves the result to `user_detail_response.json`.

---

### 3. **Testing Downstream APIs**
If the user uploaded a Postman collection:
- It loops through each request in the file.
- Dynamically replaces placeholders like:
  - `{{access_token}}`
  - `{{url}}`, `{{url_v2}}`
- Makes actual API calls using the session token and cookies.
- Captures:
  - API name, HTTP method, URL, status code, short response
- Stores results in an Excel file: `downstream_api_results.xlsx`.

---

### 4. **Download Feature**
- Allows user to download the session file (`session.json`) directly from the Streamlit UI.

---

## 📦 Files Generated
- `session.json`: Stores login tokens, cookies, and decoded JWT.
- `user_detail_response.json`: Stores user detail API response.
- `downstream_api_results.xlsx`: Stores results of downstream API calls.

---

## 🛠️ Helper Functions

### `get_env_or_input()`
- Fetches environment variable if set, otherwise asks the user.

### `extract_env_variables()`
- Extracts specific fields (`party_id`, `user_id`) from the OTP verification response.

---

## ✅ Tech Stack
- **Streamlit**: Web UI
- **Requests**: API calls
- **JWT**: Decoding token
- **Logging**: Logs for debugging
- **Pandas**: Exporting API results to Excel