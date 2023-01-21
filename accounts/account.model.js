const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
  email: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: false },
  title: { type: String, required: true },
  stripeId: { type: String },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  profileImg: { type: String },
  number: { type: Number },
  address: { type: String },
  downloads: { type: Number, default: 0 },
  acceptTerms: Boolean,
  role: { type: String, required: true },
  verificationToken: String,
  plan: { type: String, default: 'free' },
  verified: Date,
  facebook: {
    id: String,
    token: String,
    email: String,
    image: String,
  },
  google: {
    id: String,
    token: String,
    email: String,
    image: String,
  },
  resetToken: {
    token: String,
    expires: Date,
  },
  passwordReset: Date,
  created: { type: Date, default: Date.now },
  updated: Date,
});

schema.virtual('isVerified').get(function () {
  return !!(this.verified || this.passwordReset);
});

schema.set('toJSON', {
  virtuals: true,
  versionKey: false,
  transform: function (doc, ret) {
    // remove these props when object is serialized
    delete ret._id;
    delete ret.passwordHash;
  },
});

module.exports = mongoose.model('Account', schema);