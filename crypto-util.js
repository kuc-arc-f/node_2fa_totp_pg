const crypto = require('crypto');
const key = Buffer.from(process.env.TOTP_ENC_KEY || '', 'hex');
if (key.length !== 32) throw new Error('TOTP_ENC_KEY は 32バイト(hex 64文字)にしてください');

exports.encrypt = (text) => {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), enc].map((b) => b.toString('base64')).join('.');
};

exports.decrypt = (s) => {
  const [iv, tag, enc] = s.split('.').map((x) => Buffer.from(x, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
};
