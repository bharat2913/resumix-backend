const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');
const Schema = mongoose.Schema;

const schema = new Schema({
  userId: { type: String, required: true }, // unique: true,
  isDownloaded: { type: Boolean, default: false },
  documentName: { type: String, required: true }, //unique: true,
  documentData: { type: String, required: true },
  created: { type: Date, default: Date.now },
  updated: { type: Date },
});

// schema.plugin(uniqueValidator, { message: 'must be unique {VALUE}' });

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

module.exports = mongoose.model('Resume', schema);
