const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('_middleware/validate-request');
const authorize = require('_middleware/authorize');
const Role = require('_helpers/role');
const resumeService = require('./resume.service');

// routes
router.get('/', getAll);
router.post('/create', authorize(), createSchema, create);
router.get('/:id', authorize(), getById);
router.get('/getByUserId/:id', getByUserId);
router.put('/:id', authorize(), updateSchema, update);
router.post('/', authorize(Role.Admin), createSchema, create);
router.delete('/:id', _delete);

module.exports = router;

function getAll(req, res, next) {
  resumeService
    .getAll()
    .then((resumes) => res.json(resumes))
    .catch(next);
}

function getByUserId(req, res, next) {
  // users can get their own account and admins can get any account
  // if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
  //   return res.status(401).json({ message: 'Unauthorized' });
  // }
  // console.log(req.params.id);

  resumeService
    .getByUserId(req.params.id)
    .then((resume) => (resume ? res.json(resume) : res.sendStatus(404)))
    .catch(next);
}

function getById(req, res, next) {
  // users can get their own account and admins can get any account
  // if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
  //   return res.status(401).json({ message: 'Unauthorized' });
  // }
  // console.log(req.params.id);

  resumeService
    .getById(req.params.id)
    .then((resume) => (resume ? res.json(resume) : res.sendStatus(404)))
    .catch(next);
}

function createSchema(req, res, next) {
  const schema = Joi.object({
    userId: Joi.string().required(),
    isDownloaded: Joi.boolean().empty(''),
    documentName: Joi.string().required(),
    documentData: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function create(req, res, next) {
  resumeService
    .create(req.body)
    .then((resume) => res.json(resume))
    .catch(next);
}

function updateSchema(req, res, next) {
  const schemaRules = {
    userId: Joi.string().empty(''),
    isDownloaded: Joi.boolean().empty(''),
    documentName: Joi.string(),
    documentData: Joi.string().empty(''),
  };

  // // only admins can update role
  // if (req.user.role === Role.Admin) {
  //   schemaRules.role = Joi.string().valid(Role.Admin, Role.User).empty('');
  // }

  const schema = Joi.object(schemaRules).with('password', 'confirmPassword');
  validateRequest(req, next, schema);
}

function update(req, res, next) {
  // users can update their own account and admins can update any account
  // if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
  //   return res.status(401).json({ message: 'Unauthorized' });
  // }

  resumeService
    .update(req.params.id, req.body)
    .then((resume) => res.json(resume))
    .catch(next);
}

function _delete(req, res, next) {
  // users can delete their own account and admins can delete any account
  // if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
  //   return res.status(401).json({ message: 'Unauthorized' });
  // }

  resumeService
    .delete(req.params.id)
    .then(() => res.json({ message: 'Resume deleted successfully' }))
    .catch(next);
}
