import { AppError } from '../../utils/response.js';
import { ERROR_CODES } from '../../config/constants.js';

/**
 * Input validation for auth requests.
 *
 * Each validator returns a NEW object with only the allowed fields (mass-
 * assignment protection). Unknown fields are rejected, so a client can never
 * smuggle in `role`, `id`, `passwordHash`, etc.
 */

const EMAIL_MAX = 254;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 128; // bounds hashing cost per request
const NAME_MIN = 2;
const NAME_MAX = 100;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@.]+(\.[^\s@.]+)*\.[^\s@.]{2,}$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/;

const COMMON_PASSWORDS = new Set([
  'password1', 'password12', 'password123', 'passw0rd', 'qwerty123', 'qwerty12', 'abc12345', 'abcd1234',
  '1234abcd', 'iloveyou1', 'welcome1', 'welcome123', 'admin123', 'letmein1', 'monkey123', 'dragon123',
  '123456789a', 'a123456789', '1q2w3e4r', '1qaz2wsx', 'trustno1', 'cyberlens1', 'cyberlens123',
]);

export function normalizeEmail(email) {
  return String(email).normalize('NFKC').trim().toLowerCase();
}

function fail(details, message = 'Please check the highlighted fields.') {
  throw new AppError(message, { code: ERROR_CODES.VALIDATION_ERROR, status: 400, details });
}

function ensurePlainBody(body, allowed) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    fail({ body: 'Expected a JSON object.' }, 'Request body must be a JSON object.');
  }
  const unknown = Object.keys(body).filter((k) => !allowed.includes(k));
  if (unknown.length) {
    fail(Object.fromEntries(unknown.map((k) => [k, 'This field is not allowed.'])), 'Request contains fields that are not allowed.');
  }
}

export function passwordProblem(password, email) {
  if (typeof password !== 'string' || password.length === 0) return 'Password is required.';
  if (password.length < PASSWORD_MIN) return `Use at least ${PASSWORD_MIN} characters.`;
  if (password.length > PASSWORD_MAX) return `Use at most ${PASSWORD_MAX} characters.`;
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) return 'Include at least one letter and one number.';
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return 'This password is too common. Choose another.';
  if (email && password.toLowerCase() === String(email).toLowerCase()) return 'Password must not be your email address.';
  return null;
}

export function cleanFullName(value) {
  return typeof value === 'string' ? value.normalize('NFKC').trim().replace(/\s+/g, ' ') : '';
}

export function validateRegistration(body) {
  ensurePlainBody(body, ['fullName', 'email', 'password', 'confirmPassword', 'acceptTerms']);
  const details = {};

  const fullName = cleanFullName(body.fullName);
  if (!fullName) details.fullName = 'Full name is required.';
  else if (fullName.length < NAME_MIN || fullName.length > NAME_MAX) details.fullName = `Use ${NAME_MIN}-${NAME_MAX} characters.`;
  else if (CONTROL_RE.test(fullName) || /[<>]/.test(fullName)) details.fullName = 'Name contains characters that are not allowed.';

  const email = typeof body.email === 'string' ? normalizeEmail(body.email) : '';
  if (!email) details.email = 'Email is required.';
  else if (email.length > EMAIL_MAX || !EMAIL_RE.test(email)) details.email = 'Enter a valid email address.';

  const pw = passwordProblem(body.password, email);
  if (pw) details.password = pw;

  if (body.confirmPassword !== undefined && body.confirmPassword !== body.password) {
    details.confirmPassword = 'Passwords do not match.';
  }
  if (body.acceptTerms !== true) details.acceptTerms = 'You must accept the terms to create an account.';

  if (Object.keys(details).length) fail(details);
  return { fullName, email, password: body.password };
}

export function validateLogin(body) {
  ensurePlainBody(body, ['email', 'password']);
  const details = {};
  const email = typeof body.email === 'string' ? normalizeEmail(body.email) : '';
  if (!email) details.email = 'Email is required.';
  else if (email.length > EMAIL_MAX) details.email = 'Enter a valid email address.';
  if (typeof body.password !== 'string' || body.password.length === 0) details.password = 'Password is required.';
  else if (body.password.length > PASSWORD_MAX) details.password = `Use at most ${PASSWORD_MAX} characters.`;
  if (Object.keys(details).length) fail(details);
  return { email, password: body.password };
}
