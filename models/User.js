import mongoose from 'mongoose'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

const saltRounds = 14

const schema = new mongoose.Schema({
  firstName: { type: String, trim: true, maxlength: 64, required: true },
  lastName: { type: String, trim: true, maxlength: 64 },
  email: { type: String, trim: true, unique: true, maxlength: 512, required: true },
  password: { type: String, trim: true, maxlength: 70, required: true }
})

schema.methods.generateAuthToken = function() {
  const payload = {uid: this._id}
  return jwt.sign(payload, 'superSecureSecret')
}

schema.statics.authenticate = async function (email, password) {
  const user = await this.findOne({ email: email })
  const badHash = `$2b$${saltRounds}$invalidusernameaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
  const hashedPassword = user ? user.password : badHash
  const passwordDidMatch = await bcrypt.compare(password, hashedPassword)

  return passwordDidMatch ? user : null
  // remember if the email did not match, user === null
}

const Model = mongoose.model('User', schema) // factory function returns a class

export default Model

