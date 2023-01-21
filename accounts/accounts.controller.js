const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('_middleware/validate-request');
const authorize = require('_middleware/authorize');
const Role = require('_helpers/role');
const accountService = require('./account.service');

// routes
router.post('/authenticate', authenticateSchema, authenticate);
router.post(
  '/authenticate-social',
  authenticateSocialSchema,
  authenticateSocial
);
router.post('/refresh-token', refreshToken);
router.post('/revoke-token', authorize(), revokeTokenSchema, revokeToken);
router.post('/register', registerSchema, register);
router.post('/register-social', socialRegisterSchema, registerSocial);
router.post('/resend-email', emailResend);
router.post('/verify-email', verifyEmailSchema, verifyEmail);
router.post('/forgot-password', forgotPasswordSchema, forgotPassword);
router.post(
  '/validate-reset-token',
  validateResetTokenSchema,
  validateResetToken
);
router.post('/reset-password', resetPasswordSchema, resetPassword);
router.get('/', authorize(Role.Admin), getAll);
router.get('/:id', authorize(), getById);
router.post('/', authorize(Role.Admin), createSchema, create);
router.put('/:id', authorize(), updateSchema, update);
router.delete('/:id', authorize(), _delete);
router.get('/downloads/:id', downloadsById);
router.post('/downloads/:id', updateDownloadsById);

module.exports = router;

function authenticateSchema(req, res, next) {
  const schema = Joi.object({
    email: Joi.string().required(),
    password: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function downloadsById(req, res, next) {
  const id = req.params.id;
  // console.log();
  accountService
    .getDownloadsById(id)
    .then((resp) => {
      // console.log(res);
      res.json(resp);
    })
    .catch(next);
}
function updateDownloadsById(req, res, next) {
  const id = req.params.id;
  const { downloads } = req.body;
  // console.log(id, downloads);
  accountService
    .updateDownloadsById(id, { downloads })
    .then((resp) => {
      // console.log(res);
      res.json(resp);
    })
    .catch(next);
}

function authenticate(req, res, next) {
  const { email, password } = req.body;
  const ipAddress = req.ip;
  accountService
    .authenticate({ email, password, ipAddress })
    .then(({ refreshToken, ...account }) => {
      setTokenCookie(res, refreshToken);
      res.json(account);
    })
    .catch(next);
}

function authenticateSocialSchema(req, res, next) {
  const schema = Joi.object({
    email: Joi.string().required(),
    type: Joi.string().required(),
    token: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function authenticateSocial(req, res, next) {
  const { email, type, token } = req.body;
  const ipAddress = req.ip;
  accountService
    .authenticateSocial({ email, type, token, ipAddress })
    .then(({ refreshToken, ...account }) => {
      setTokenCookie(res, refreshToken);
      res.json(account);
    })
    .catch(next);
}

function refreshToken(req, res, next) {
  const token = req.cookies.refreshToken;
  const ipAddress = req.ip;
  accountService
    .refreshToken({ token, ipAddress })
    .then(({ refreshToken, ...account }) => {
      setTokenCookie(res, refreshToken);
      res.json(account);
    })
    .catch(next);
}

function revokeTokenSchema(req, res, next) {
  const schema = Joi.object({
    token: Joi.string().empty(''),
  });
  validateRequest(req, next, schema);
}

function revokeToken(req, res, next) {
  // accept token from request body or cookie
  const token = req.body.token || req.cookies.refreshToken;
  const ipAddress = req.ip;

  if (!token) return res.status(400).json({ message: 'Token is required' });

  // users can revoke their own tokens and admins can revoke any tokens
  if (!req.user.ownsToken(token) && req.user.role !== Role.Admin) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  accountService
    .revokeToken({ token, ipAddress })
    .then(() => res.json({ message: 'Token revoked' }))
    .catch(next);
}

function registerSchema(req, res, next) {
  const schema = Joi.object({
    title: Joi.string().required(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().required(),
    stripeId: Joi.string().empty(''),
    image: Joi.string(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
    acceptTerms: Joi.boolean().valid(true).required(),
  });
  validateRequest(req, next, schema);
}

function register(req, res, next) {
  accountService
    .register(req.body, req.get('origin'))
    .then(() => {
      // console.log(res);
      res.json({
        message: 'Registration successful, Please login',
      });
    })
    .catch(next);
}
function socialRegisterSchema(req, res, next) {
  const schema = Joi.object({
    title: Joi.string().required(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().required(),
    stripeId: Joi.string().empty(''),
    'facebook.id': Joi.string(),
    'facebook.email': Joi.string().email(),
    'facebook.token': Joi.string(),
    'facebook.image': Joi.string(),

    'google.id': Joi.string(),
    'google.email': Joi.string().email(),
    'google.token': Joi.string(),
    'google.image': Joi.string(),
    acceptTerms: Joi.boolean().valid(true).required(),
  });
  validateRequest(req, next, schema);
}
function registerSocial(req, res, next) {
  accountService
    .registerSocial(req.body)
    .then(() => res.json({ message: 'Registration successful' }))
    .catch(next);
}
function emailResend(req, res, next) {
  accountService
    .resendEmail(req.body, req.get('origin'))
    .then(() =>
      res.json({
        message:
          'Email sent successfully, please check your email for verification instructions',
      })
    )
    .catch(next);
}

function verifyEmailSchema(req, res, next) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function verifyEmail(req, res, next) {
  accountService
    .verifyEmail(req.body)
    .then(() =>
      res.json({ message: 'Verification successful, you can now login' })
    )
    .catch(next);
}

function forgotPasswordSchema(req, res, next) {
  const schema = Joi.object({
    email: Joi.string().email().required(),
  });
  validateRequest(req, next, schema);
}

function forgotPassword(req, res, next) {
  accountService
    .forgotPassword(req.body, req.get('origin'))
    .then(() =>
      res.json({
        message: 'Please check your email for password reset instructions',
      })
    )
    .catch(next);
}

function validateResetTokenSchema(req, res, next) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function validateResetToken(req, res, next) {
  accountService
    .validateResetToken(req.body)
    .then(() => res.json({ message: 'Token is valid' }))
    .catch(next);
}

function resetPasswordSchema(req, res, next) {
  const schema = Joi.object({
    token: Joi.string().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
  });
  validateRequest(req, next, schema);
}

function resetPassword(req, res, next) {
  accountService
    .resetPassword(req.body)
    .then(() =>
      res.json({ message: 'Password reset successful, you can now login' })
    )
    .catch(next);
}

function getAll(req, res, next) {
  console.log('hello');
  accountService
    .getAll()
    .then((accounts) => res.json(accounts))
    .catch(next);
}

function getById(req, res, next) {
  // users can get their own account and admins can get any account
  if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  accountService
    .getById(req.params.id)
    .then((account) => (account ? res.json(account) : res.sendStatus(404)))
    .catch(next);
}

function createSchema(req, res, next) {
  const schema = Joi.object({
    title: Joi.string().required(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
    role: Joi.string().valid(Role.Admin, Role.User).required(),
    stripeId: Joi.string().empty(''),
  });
  validateRequest(req, next, schema);
}

function create(req, res, next) {
  accountService
    .create(req.body)
    .then((account) => res.json(account))
    .catch(next);
}

function updateSchema(req, res, next) {
  const schemaRules = {
    title: Joi.string().empty(''),
    firstName: Joi.string().empty(''),
    lastName: Joi.string().empty(''),
    email: Joi.string().email().empty(''),
    password: Joi.string().min(6).empty(''),
    confirmPassword: Joi.string().valid(Joi.ref('password')).empty(''),
    number: Joi.number().empty(''),
    address: Joi.string().empty(''),
    profileImg: Joi.string().empty(''),
    stripeId: Joi.string().empty(''),
    // image: Joi.string(),
  };

  // only admins can update role
  if (req.user.role === Role.Admin) {
    schemaRules.role = Joi.string().valid(Role.Admin, Role.User).empty('');
  }

  const schema = Joi.object(schemaRules).with('password', 'confirmPassword');
  validateRequest(req, next, schema);
}

function update(req, res, next) {
  // users can update their own account and admins can update any account
  if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  accountService
    .update(req.params.id, req.body)
    .then((account) => res.json(account))
    .catch(next);
}

function _delete(req, res, next) {
  // users can delete their own account and admins can delete any account
  if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  accountService
    .delete(req.params.id)
    .then(() => res.json({ message: 'Account deleted successfully' }))
    .catch(next);
}

// helper functions

function setTokenCookie(res, token) {
  // create cookie with refresh token that expires in 7 days
  const cookieOptions = {
    httpOnly: true,
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  };
  res.cookie('refreshToken', token, cookieOptions);
}
