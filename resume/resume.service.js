const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const Role = require('_helpers/role');

module.exports = {
  getAll,
  getById,
  getByUserId,
  create,
  update,
  basicDetails,
  delete: _delete,
};

async function getAll() {
  const resume = await db.Resume.find();
  return resume.map((x) => basicDetails(x));
}

async function getById(id) {
  const resume = await getResume(id);
  // return { name: 'getById' };
  return basicDetails(resume);
}

async function getByUserId(userId) {
  const resume = await getUserResume(userId);
  // return basicDetails(resume);
  return resume.map((x) => basicDetails(x));
}

async function create(params) {
  // validate
  // if (await db.Account.findOne({ email: params.email })) {
  //   throw 'Email "' + params.email + '" is already registered';
  // }

  const resume = new db.Resume(params);
  resume.verified = Date.now();

  // // hash password
  // resume.passwordHash = hash(params.password);

  // save resume
  await resume.save();

  return basicDetails(resume);
}

async function update(id, params) {
  const resume = await getResume(id);

  // validate (if email was changed)
  // if (
  //   params.email &&
  //   resume.email !== params.email &&
  //   (await db.Account.findOne({ email: params.email }))
  // ) {
  //   throw 'Email "' + params.email + '" is already taken';
  // }

  // hash password if it was entered
  // if (params.password) {
  //   params.passwordHash = hash(params.password);
  // }

  // copy params to resume and save
  Object.assign(resume, params);
  resume.updated = Date.now();
  await resume.save();

  return basicDetails(resume);
}

async function _delete(id) {
  const resume = await getResume(id);
  await resume.remove();
}

// helper functions

async function getResume(id) {
  if (!db.isValidId(id)) throw 'Resume not found';
  const resume = await db.Resume.findById(id);
  if (!resume) throw 'Resume not found';
  return resume;
}

async function getUserResume(userId) {
  if (!db.isValidId(userId)) throw 'Resume not found';
  const resume = await db.Resume.find({ userId: userId });
  if (!resume || resume.length === 0) throw 'Resume not found';
  return resume;
}

function basicDetails(account) {
  const { id, userId, isDownloaded, documentName, documentData, created } =
    account;
  return { id, userId, isDownloaded, documentName, documentData, created };
}
