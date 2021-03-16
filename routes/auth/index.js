import express from 'express'
import sanitizeBody from '../../middleware/sanitizeBody.js'
import User from '../../models/User.js'
const router = express.Router()

// Register a new user
router.post('/users', sanitizeBody, async (req, res) => {
  try {
    let newUser = new User(req.sanitizedBody)
    await newUser.save()
    res.status(201).send({ data: newUser })
  } catch (err) {
    debug(err)
    res.status(500).send({
      errors: [
        {
          status: '500',
          title: 'Server error',
          description: 'Problem saving document to the database.',
        },
      ],
    })
  }
})

export default router
