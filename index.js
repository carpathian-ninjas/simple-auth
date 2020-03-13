const timingSafeEqual = require('crypto').timingSafeEqual;
const Buffer = require('safe-buffer').Buffer;

const USER_PASS_REGEXP = /^([^:]*):(.*)$/;

function checkAuth(req, key) {
  if (!req) throw new TypeError('argument req is required');

  if (typeof req !== 'object') throw new TypeError('argument req is required to be an object');

  if (!req.headers || typeof req.headers !== 'object')
    throw new TypeError('argument req is required to have headers property');

  const cookie = req.headers.cookie;
  if (!cookie) return undefined;

  const rawCookie = cookie.split(';').find(c => c.trim().startsWith(`${key}=`));
  if (!rawCookie) return undefined;

  const userPass = USER_PASS_REGEXP.exec(Buffer.from(decodeURIComponent(rawCookie.split('=')[1]), 'base64').toString());
  return userPass ? {
    name: userPass[1],
    pass: userPass[2]
  } : undefined;
}

function safeCompare(userInput, secret) {
  const userInputLength = Buffer.byteLength(userInput);
  const secretLength = Buffer.byteLength(secret);

  const userInputBuffer = Buffer.alloc(userInputLength, 0, 'utf8');
  userInputBuffer.write(userInput);
  const secretBuffer = Buffer.alloc(userInputLength, 0, 'utf8');
  secretBuffer.write(secret);

  return !!(timingSafeEqual(userInputBuffer, secretBuffer) & userInputLength === secretLength)
}

function ensureFunction(option, defaultValue) {
  if(typeof option === 'undefined')
    return function() { return defaultValue };

  if(typeof option !== 'function')
    return function() { return option };

  return option;
}

function buildMiddleware(options) {
  const authorizer = options.authorizer;
  const unprotected = options.unprotected || ['/login'];
  const key = options.key || 'token';
  const customUnauthorizer = options.customUnauthorizer || false;
  const isAsync = options.authorizeAsync !== undefined ? !!options.authorizeAsync : false;
  const getResponseBody = ensureFunction(options.unauthorizedResponse, '');

  return function authMiddleware(req, res, next) {
    if (unprotected.indexOf(req.url) !== -1 && req.method === 'GET') return next();

    const authentication = checkAuth(req, key);

    if(!authentication) return unauthorized();

    if(isAsync) return authorizer(authentication.name, authentication.pass, authorizerCallback);

    return (!authorizer(authentication.name, authentication.pass)) ? unauthorized() : next();

    function unauthorized() {
      if(customUnauthorizer) {
        return customUnauthorizer(res);
      }

      const response = getResponseBody(req);

      if(typeof response === 'string')
        return res.status(401).send(response);

      return res.status(401).json(response);
    }

    function authorizerCallback(err, approved) {
      return approved ? next() : unauthorized();
    }
  }
}

buildMiddleware.safeCompare = safeCompare;
module.exports = buildMiddleware;
