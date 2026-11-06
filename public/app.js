console.log("#app.jsが読み込まれました。");

const $ = (id) => document.getElementById(id);
const show = (id, v) => $(id).classList.toggle('hidden', !v);
const msg = (t) => ($('msg').textContent = t || '');

async function api(url, body) {
  const r = await fetch(url, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || 'エラーが発生しました');
  return data;
}

async function loadHome() {
  try {
    const me = await api('/api/me');
    $('who').textContent = me.email;
    $('twofa').textContent = me.totp_enabled ? '有効' : '無効';
    show('authBox', false); show('otpBox', false); show('homeBox', true);
    show('setupArea', !me.totp_enabled); show('qrArea', false);
  } catch { show('authBox', true); show('otpBox', false); show('homeBox', false); }
}

const registerBtn = document.getElementById("registerBtn");
registerBtn.addEventListener('click', async() => {
  //alert('registerBtn 実行されました！');
  try { 
    await api('/api/register', { email: $('email').value, password: $('password').value }); 
    msg('登録しました。ログインしてください。'); 
  }
  catch (e) { msg(e.message); }
});

$('loginBtn').onclick = async () => {
  try {
    const r = await api('/api/login', { email: $('email').value, password: $('password').value });
    msg('');
    if (r.need2fa) { show('authBox', false); show('otpBox', true); $('otp').focus(); }
    else loadHome();
  } catch (e) { msg(e.message); }
};
$('otpBtn').onclick = async () => {
  try { await api('/api/login/2fa', { token: $('otp').value }); msg(''); $('otp').value = ''; loadHome(); }
  catch (e) { msg(e.message); }
};
$('setupBtn').onclick = async () => {
  try { const r = await api('/api/2fa/setup', {}); $('qr').src = r.qr; $('secret').textContent = r.secret; show('qrArea', true); }
  catch (e) { msg(e.message); }
};
$('enableBtn').onclick = async () => {
  try { await api('/api/2fa/enable', { token: $('enableOtp').value }); msg(''); loadHome(); }
  catch (e) { msg(e.message); }
};
$('logoutBtn').onclick = async () => { await api('/api/logout', {}); location.reload(); };

loadHome();
