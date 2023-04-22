import cors from 'cors';
import debug from 'debug';
import redis from '@umami/redis-client';
import { getAuthToken, parseShareToken } from 'lib/auth';
import { ROLES } from 'lib/constants';
import { secret } from 'lib/crypto';
import { findSession } from 'lib/session';
import {
  badRequest,
  createMiddleware,
  forbidden,
  parseSecureToken,
  tooManyRequest,
  unauthorized,
} from 'next-basics';
import { NextApiRequestCollect } from 'pages/api/send';
import { getUser } from '../queries';

const log = debug('umami:middleware');

const whitelist = [
  'https://umami.bmpi.dev',
  'https://www.bmpi.dev',
  'https://feed.bmpi.dev',
  'https://money.bmpi.dev',
  'https://www.myinvestpilot.com',
  'https://www.myinvestpilot.com/',
  'https://www.free4.chat',
  'https://dev-notes.free4.chat',
  'https://www.myreader.io',
  'https://www.myreader.io/',
  'https://www.chat2invest.com',
  'https://www.chat2invest.com/',
  'https://www.mywriter.ink',
  'https://www.mywriter.ink/',
  'https://www.i365.tech',
  'https://www.i365.tech/',
];
const corsOptions = {
  origin: function (origin, callback) {
    // eslint-disable-next-line no-console
    console.info(origin);
    if (origin === undefined || whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error(origin + ' is not allowed by CORS whitelist'));
    }
  },
};

export const useCors = createMiddleware(
  cors({
    ...corsOptions,
    // Cache CORS preflight request 24 hours by default
    maxAge: Number(process.env.CORS_MAX_AGE) || 86400,
  }),
);

export const useSession = createMiddleware(async (req, res, next) => {
  try {
    const session = await findSession(req as NextApiRequestCollect);

    if (!session) {
      log('useSession: Session not found');
      return badRequest(res, 'Session not found.');
    }

    (req as any).session = session;
  } catch (e: any) {
    if (e.message === 'Usage Limit.') {
      return tooManyRequest(res, e.message);
    }
    if (e.message.startsWith('Website not found:')) {
      return forbidden(res, e.message);
    }
    return badRequest(res, e.message);
  }

  next();
});

export const useAuth = createMiddleware(async (req, res, next) => {
  const token = getAuthToken(req);
  const payload = parseSecureToken(token, secret());
  const shareToken = await parseShareToken(req as any);

  let user = null;
  const { userId, authKey, grant } = payload || {};

  if (userId) {
    user = await getUser(userId);
  } else if (redis.enabled && authKey) {
    const key = await redis.client.get(authKey);

    if (key?.userId) {
      user = await getUser(key.userId);
    }
  }

  if (process.env.NODE_ENV === 'development') {
    log('useAuth:', { token, shareToken, payload, user, grant });
  }

  if (!user?.id && !shareToken) {
    log('useAuth: User not authorized');
    return unauthorized(res);
  }

  if (user) {
    user.isAdmin = user.role === ROLES.admin;
  }

  (req as any).auth = {
    user,
    grant,
    token,
    shareToken,
    authKey,
  };

  next();
});

export const useValidate = async (schema, req, res) => {
  return createMiddleware(async (req: any, res, next) => {
    try {
      const rules = schema[req.method];

      if (rules) {
        rules.validateSync({ ...req.query, ...req.body });
      }
    } catch (e: any) {
      return badRequest(res, e.message);
    }

    next();
  })(req, res);
};
