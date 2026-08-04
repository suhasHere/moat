use axum::response::Html;

pub async fn landing() -> Html<&'static str> {
    Html(LANDING_HTML)
}

pub async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

pub async fn app_js() -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        APP_JS,
    )
}

pub async fn style_css() -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css")],
        STYLE_CSS,
    )
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Moat — MoQ Auth Token Service</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<div id="app">
  <header>
    <h1>Moat</h1>
    <p class="tagline">MoQ Auth Token Service</p>
    <div id="user-bar" class="hidden">
      <span id="user-info"></span>
      <button onclick="logout()">Logout</button>
    </div>
  </header>

  <main>
    <!-- Login Section -->
    <section id="login-section">
      <div class="card">
        <h2>Sign In</h2>
        <div class="login-options">
          <div class="guest-login">
            <input type="text" id="guest-name" placeholder="Display name" maxlength="64">
            <button onclick="guestLogin()">Join as Guest</button>
          </div>
          <div class="divider"><span>or</span></div>
          <button id="google-btn" class="google-btn" onclick="googleLogin()">
            Sign in with Google
          </button>
        </div>
      </div>
    </section>

    <!-- Dashboard Section -->
    <section id="dashboard-section" class="hidden">
      <div class="card">
        <h2>Rooms</h2>
        <div id="room-list"></div>
        <div class="create-room">
          <input type="text" id="new-room-name" placeholder="Room name">
          <input type="text" id="new-room-ns" placeholder="Namespace prefix (e.g. conference/room-1)">
          <button onclick="createRoom()">Create Room</button>
        </div>
      </div>

      <div id="room-detail" class="card hidden">
        <h2 id="room-title"></h2>
        <p id="room-ns" class="muted"></p>

        <h3>Members</h3>
        <div id="member-list"></div>
        <div class="add-member">
          <input type="text" id="add-member-email" placeholder="User email or ID">
          <select id="add-member-role">
            <option value="subscriber">Subscriber</option>
            <option value="publisher">Publisher</option>
            <option value="admin">Admin</option>
          </select>
          <button onclick="addMember()">Add</button>
        </div>

        <h3>Get Token</h3>
        <div class="token-request">
          <select id="token-role">
            <option value="subscriber">Subscriber</option>
            <option value="publisher">Publisher</option>
            <option value="pubsub">Pub+Sub</option>
          </select>
          <button onclick="getToken()">Mint Token</button>
        </div>
        <div id="token-result" class="hidden">
          <pre id="token-value"></pre>
          <button onclick="copyToken()">Copy to Clipboard</button>
          <p class="muted">Token type: <code id="token-type-val"></code> | Expires in: <span id="token-expires"></span>s</p>
        </div>
      </div>
    </section>
  </main>
</div>
<script src="/app.js"></script>
</body>
</html>"#;

const STYLE_CSS: &str = r#"* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #0f1117; color: #e4e4e7; min-height: 100vh;
}
#app { max-width: 900px; margin: 0 auto; padding: 20px; }
header { text-align: center; margin-bottom: 30px; padding: 20px 0; border-bottom: 1px solid #27272a; }
header h1 { font-size: 2.5rem; background: linear-gradient(135deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.tagline { color: #71717a; margin-top: 4px; }
#user-bar { margin-top: 12px; display: flex; align-items: center; justify-content: center; gap: 12px; }
#user-bar button { padding: 4px 12px; background: #27272a; border: 1px solid #3f3f46; border-radius: 6px; color: #a1a1aa; cursor: pointer; }
#user-bar button:hover { background: #3f3f46; }
.hidden { display: none !important; }
.card { background: #18181b; border: 1px solid #27272a; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
.card h2 { margin-bottom: 16px; font-size: 1.3rem; }
.card h3 { margin: 20px 0 10px; font-size: 1rem; color: #a1a1aa; }
input, select { background: #27272a; border: 1px solid #3f3f46; border-radius: 6px; padding: 10px 14px; color: #e4e4e7; font-size: 14px; }
input:focus, select:focus { outline: none; border-color: #3b82f6; }
button { padding: 10px 20px; background: #3b82f6; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; }
button:hover { background: #2563eb; }
.login-options { display: flex; flex-direction: column; gap: 16px; }
.guest-login { display: flex; gap: 8px; }
.guest-login input { flex: 1; }
.divider { display: flex; align-items: center; gap: 12px; color: #52525b; }
.divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: #27272a; }
.google-btn { background: #fff; color: #333; font-weight: 600; }
.google-btn:hover { background: #f1f1f1; }
.create-room { display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap; }
.create-room input { flex: 1; min-width: 150px; }
.add-member { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
.add-member input { flex: 1; }
.token-request { display: flex; gap: 8px; align-items: center; }
#token-result { margin-top: 12px; padding: 12px; background: #0f0f12; border: 1px solid #27272a; border-radius: 8px; }
#token-value { word-break: break-all; font-size: 11px; color: #86efac; max-height: 80px; overflow-y: auto; margin-bottom: 8px; }
.muted { color: #71717a; font-size: 12px; margin-top: 4px; }
code { background: #27272a; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
#room-list { display: flex; flex-direction: column; gap: 8px; }
.room-item { display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background: #1f1f23; border-radius: 8px; cursor: pointer; transition: background 0.2s; }
.room-item:hover { background: #27272a; }
.room-item .name { font-weight: 600; }
.room-item .ns { font-size: 12px; color: #71717a; }
.member-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: #1f1f23; border-radius: 6px; margin-bottom: 6px; }
.member-item .role { font-size: 11px; padding: 2px 8px; border-radius: 10px; background: #27272a; color: #a1a1aa; }
.member-item .role.admin { background: #7c3aed22; color: #a78bfa; }
.member-item .role.publisher { background: #059669aa; color: #6ee7b7; }
.member-item .role.subscriber { background: #2563eb22; color: #93c5fd; }
"#;

const APP_JS: &str = r#"
const API = '';
let session = null;
let currentRoom = null;

function init() {
  const saved = localStorage.getItem('moat_session');
  if (saved) {
    session = JSON.parse(saved);
    showDashboard();
  }
}

async function guestLogin() {
  const name = document.getElementById('guest-name').value.trim();
  if (!name) return alert('Enter a display name');

  const res = await fetch(API + '/v1/auth/guest', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({display_name: name})
  });
  if (!res.ok) return alert('Login failed: ' + (await res.json()).error);

  session = await res.json();
  localStorage.setItem('moat_session', JSON.stringify(session));
  showDashboard();
}

async function googleLogin() {
  alert('Google login requires MOAT_GOOGLE_CLIENT_ID to be configured on the server.');
}

function logout() {
  session = null;
  currentRoom = null;
  localStorage.removeItem('moat_session');
  document.getElementById('login-section').classList.remove('hidden');
  document.getElementById('dashboard-section').classList.add('hidden');
  document.getElementById('user-bar').classList.add('hidden');
}

function showDashboard() {
  document.getElementById('login-section').classList.add('hidden');
  document.getElementById('dashboard-section').classList.remove('hidden');
  document.getElementById('user-bar').classList.remove('hidden');
  document.getElementById('user-info').textContent = session.display_name || session.email;
  loadRooms();
}

async function apiFetch(path, opts = {}) {
  const headers = {'Content-Type': 'application/json', ...opts.headers};
  if (session) headers['Authorization'] = 'Bearer ' + session.session_token;
  return fetch(API + path, {...opts, headers});
}

async function loadRooms() {
  const res = await apiFetch('/v1/rooms');
  const rooms = await res.json();
  const list = document.getElementById('room-list');
  if (rooms.length === 0) {
    list.innerHTML = '<p class="muted">No rooms yet. Create one below.</p>';
    return;
  }
  list.innerHTML = rooms.map(r => `
    <div class="room-item" onclick="selectRoom('${r.id}')">
      <div><div class="name">${r.name}</div><div class="ns">${r.namespace_prefix}</div></div>
    </div>
  `).join('');
}

async function createRoom() {
  const name = document.getElementById('new-room-name').value.trim();
  const ns = document.getElementById('new-room-ns').value.trim();
  if (!name || !ns) return alert('Fill in room name and namespace');

  const res = await apiFetch('/v1/rooms', {
    method: 'POST',
    body: JSON.stringify({name, namespace_prefix: ns})
  });
  if (!res.ok) return alert('Error: ' + (await res.json()).error);
  document.getElementById('new-room-name').value = '';
  document.getElementById('new-room-ns').value = '';
  loadRooms();
}

async function selectRoom(roomId) {
  currentRoom = roomId;
  const res = await apiFetch('/v1/rooms/' + roomId);
  const room = await res.json();

  document.getElementById('room-detail').classList.remove('hidden');
  document.getElementById('room-title').textContent = room.name;
  document.getElementById('room-ns').textContent = 'Namespace: ' + room.namespace_prefix;
  document.getElementById('token-result').classList.add('hidden');

  loadMembers(roomId);
}

async function loadMembers(roomId) {
  const res = await apiFetch('/v1/rooms/' + roomId + '/members');
  const members = await res.json();
  const list = document.getElementById('member-list');
  if (members.length === 0) {
    list.innerHTML = '<p class="muted">No members. Add yourself or others below.</p>';
    return;
  }
  list.innerHTML = members.map(m => `
    <div class="member-item">
      <span>${m.user_id}</span>
      <span class="role ${m.role}">${m.role}</span>
    </div>
  `).join('');
}

async function addMember() {
  const input = document.getElementById('add-member-email').value.trim();
  const role = document.getElementById('add-member-role').value;
  if (!input || !currentRoom) return;

  const res = await apiFetch('/v1/rooms/' + currentRoom + '/members', {
    method: 'POST',
    body: JSON.stringify({user_id: input, role})
  });
  if (!res.ok) return alert('Error: ' + (await res.json()).error);
  document.getElementById('add-member-email').value = '';
  loadMembers(currentRoom);
}

async function getToken() {
  if (!currentRoom) return;
  const role = document.getElementById('token-role').value;

  const res = await apiFetch('/v1/token', {
    method: 'POST',
    body: JSON.stringify({room_id: currentRoom, role})
  });
  if (!res.ok) return alert('Error: ' + (await res.json()).error);

  const data = await res.json();
  document.getElementById('token-result').classList.remove('hidden');
  document.getElementById('token-value').textContent = data.token;
  document.getElementById('token-type-val').textContent = data.token_type;
  document.getElementById('token-expires').textContent = data.expires_in;
}

function copyToken() {
  const val = document.getElementById('token-value').textContent;
  navigator.clipboard.writeText(val);
}

init();
"#;

const LANDING_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Moat — MoQ Auth Token Service</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #0f1117; color: #e4e4e7; min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
}
.container { max-width: 720px; padding: 40px 24px; text-align: center; }
h1 {
  font-size: 3.5rem; font-weight: 800;
  background: linear-gradient(135deg, #3b82f6, #8b5cf6);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  margin-bottom: 8px;
}
.tagline { color: #a1a1aa; font-size: 1.2rem; margin-bottom: 40px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 40px; }
.card {
  background: #18181b; border: 1px solid #27272a; border-radius: 12px;
  padding: 24px; text-align: left; transition: border-color 0.2s;
}
.card:hover { border-color: #3b82f6; }
.card h3 { font-size: 1rem; margin-bottom: 8px; color: #f4f4f5; }
.card p { font-size: 0.85rem; color: #71717a; line-height: 1.5; }
.links { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
.links a {
  display: inline-block; padding: 12px 28px; border-radius: 8px;
  font-size: 0.95rem; font-weight: 600; text-decoration: none; transition: background 0.2s;
}
.links .primary { background: #3b82f6; color: #fff; }
.links .primary:hover { background: #2563eb; }
.links .secondary { background: #27272a; color: #e4e4e7; border: 1px solid #3f3f46; }
.links .secondary:hover { background: #3f3f46; }
.health { margin-top: 40px; font-size: 0.8rem; color: #52525b; }
.health span { color: #4ade80; }
</style>
</head>
<body>
<div class="container">
  <h1>Moat</h1>
  <p class="tagline">Auth &amp; token service for Media over QUIC relays</p>

  <div class="cards">
    <div class="card">
      <h3>Authentication</h3>
      <p>Guest login, Google OAuth, and Privacy Pass (RFC 9578) for anonymous attestation.</p>
    </div>
    <div class="card">
      <h3>Room Management</h3>
      <p>Create rooms with namespace prefixes, manage members and roles, share invite links.</p>
    </div>
    <div class="card">
      <h3>Token Minting</h3>
      <p>Scoped access tokens (publish/subscribe) for MoQ relays, with configurable lifetime.</p>
    </div>
  </div>

  <div class="links">
    <a href="/docs/" class="primary">API Documentation</a>
    <a href="/app" class="secondary">Dashboard</a>
    <a href="/health" class="secondary">Health Check</a>
  </div>

  <p class="health"><span>&#9679;</span> Service running</p>
</div>
</body>
</html>"#;
