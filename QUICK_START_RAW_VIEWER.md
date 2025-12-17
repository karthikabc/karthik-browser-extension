# Quick Start: Raw HTTP Viewer

## What's New? 🎉

You can now see **complete raw HTTP requests and responses** in a beautiful side-by-side view!

## Quick Demo

### Before (Old View)
```
Call Item
├── Time: 10:30:45
├── Status: 200
└── [Copy cURL]
```

### After (New View) ✨
```
┌────────────────────────────────────────────────────────────┐
│ Time: 10:30:45  Status: 200  [📄 View Raw]  [📋 Copy cURL]│
└────────────────────────────────────────────────────────────┘

Click "📄 View Raw" to see:

┌──────────────────────────────┬─────────────────────────────┐
│  📤 REQUEST (Yellow)         │  📥 RESPONSE (Blue)         │
├──────────────────────────────┼─────────────────────────────┤
│                              │                             │
│ POST /api/login HTTP/1.1     │ HTTP/1.1 200 OK             │
│ Host: api.example.com        │ content-type: app/json      │
│ Content-Type: app/json       │ set-cookie: session=...     │
│ Authorization: Bearer...     │ x-rate-limit: 99            │
│                              │                             │
│ {                            │ ⚠️ Response body not        │
│   "username": "***",         │ available (browser limit)   │
│   "password": "***"          │                             │
│ }                            │                             │
│                              │                             │
│ [📋 Copy Request]            │ [📋 Copy Response]          │
└──────────────────────────────┴─────────────────────────────┘
```

## How to Use (3 Steps)

### Step 1: Click an Endpoint
Find any API call in the left panel

### Step 2: Click "View Raw"
In the Recent Calls section, click the **"📄 View Raw"** button

### Step 3: See Everything!
- **Left column (yellow)** = Complete HTTP request
- **Right column (blue)** = HTTP response headers and status

## What You Can Do

### ✅ Copy Complete Request
```http
POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer ***REDACTED***

{
  "name": "John Doe",
  "email": "john@example.com"
}
```
Click **"📋 Copy Request"** → Paste anywhere!

### ✅ Copy Response Headers
```http
HTTP/1.1 201 Created
content-type: application/json
location: /api/users/12345
x-rate-limit-remaining: 98
```
Click **"📋 Copy Response"** → Paste anywhere!

### ✅ Compare Multiple Calls
Open raw view for several calls to compare:
- Different headers
- Different request bodies
- Different response codes

### ✅ Hide When Done
Click **"🔼 Hide Raw"** to collapse and save space

## Real-World Examples

### Example 1: Login Request
```http
📤 REQUEST:
POST /api/auth/login HTTP/1.1
Host: auth.myapp.com
Content-Type: application/json

{
  "username": "BMhAHGf1lQkmcabqwSpTnH+5M9vBQA==|...",
  "password": "IdZMA2rdzVBi|Qhk9eJunvTlOVP/ZnwNZPw=="
}

📥 RESPONSE:
HTTP/1.1 200 OK
set-cookie: session=abc123; HttpOnly; Secure
x-csrf-token: xyz789
```

### Example 2: API with Query Params
```http
📤 REQUEST:
GET /api/products?category=electronics&sort=price&page=1 HTTP/1.1
Host: api.shop.com
Accept: application/json
Authorization: Bearer token123

📥 RESPONSE:
HTTP/1.1 200 OK
x-total-count: 145
x-page-count: 15
cache-control: max-age=300
```

### Example 3: File Upload
```http
📤 REQUEST:
POST /api/upload HTTP/1.1
Host: cdn.myapp.com
Content-Type: multipart/form-data
Content-Length: 12345

{
  "file": "document.pdf",
  "metadata": {...}
}

📥 RESPONSE:
HTTP/1.1 201 Created
location: /files/abc123def456
x-upload-id: upload_789
```

## Key Features

### 🎨 Color-Coded
- **Yellow (Request)** - What you send
- **Blue (Response)** - What you receive

### 📏 Space-Efficient
- Scrollable columns (max 600px height)
- Collapsible (click to hide/show)
- Side-by-side on wide screens
- Stacked on narrow screens

### 🔒 Security-Aware
Sensitive data automatically redacted:
- `Authorization: Bearer ***REDACTED***`
- `X-API-Key: ***REDACTED***`
- `"password": "***REDACTED***"`

### 📋 Easy Copy
One-click copy for:
- Full request (for testing)
- Response headers (for analysis)
- Perfect for documentation

## Use Cases

### 🐛 Debugging
"Why is my API call failing?"
→ Click View Raw → See exact headers sent → Find the issue!

### 📝 Documentation
Need to document your API?
→ Click View Raw → Copy Request → Paste in docs!

### 🧪 Testing
Want to test the same call with modifications?
→ Click Copy Request → Paste in Postman/curl → Modify → Test!

### 🔍 Security Review
Checking what data is sent?
→ Click View Raw → Review all headers and body → Verify security!

### 🚀 Sharing with Team
"Look at this weird API behavior!"
→ Click View Raw → Screenshot → Share with team!

## Tips

### Tip 1: Use Ctrl+F to Search
Once raw view is open, use Ctrl+F to search within the request/response

### Tip 2: Compare Multiple Calls
Open View Raw for 2-3 consecutive calls to spot differences

### Tip 3: Keep It Open
Leave raw view open while debugging, it updates as you interact with the site

### Tip 4: Screenshot for Documentation
Raw view looks professional in screenshots for API documentation

## Important Note

### ⚠️ Response Body Not Available
Chrome extensions **cannot** capture response bodies (browser security limitation).

**To see response bodies:**
1. Open Chrome DevTools (F12)
2. Go to Network tab
3. Click the request
4. View Response tab

But you **can** see:
- ✅ Response status code
- ✅ All response headers
- ✅ Complete request (including body)

## Quick Comparison

| Feature | Old View | New Raw View |
|---------|----------|--------------|
| Request Headers | Hidden in collapsed section | Visible in raw format |
| Request Body | Hidden in collapsed section | Visible in raw format |
| Response Headers | Hidden in collapsed section | Visible in raw format |
| HTTP Protocol | Not shown | Complete HTTP format |
| Layout | Vertical sections | Side-by-side columns |
| Copy | Only cURL | Request + Response individually |
| Space Usage | Takes vertical space | Efficient grid layout |

## What Changed?

### New UI Elements
- **"📄 View Raw" button** - Opens raw HTTP view
- **Request column** (yellow background)
- **Response column** (blue background)
- **Copy buttons** for each column
- **"🔼 Hide Raw" button** - Collapses view

### Better Space Utilization
- Side-by-side layout uses horizontal space
- Scrollable columns prevent page bloat
- Collapsible design shows only when needed
- Responsive design adapts to screen size

## Get Started Now!

1. ✅ **Reload extension** at `chrome://extensions`
2. ✅ **Open DevTools** and go to API Mapper
3. ✅ **Click any endpoint** in the left panel
4. ✅ **Scroll to Recent Calls**
5. ✅ **Click "📄 View Raw"**
6. ✅ **See your complete HTTP request and response!**

---

**Enjoy your new raw HTTP viewer! 🎉📄**
