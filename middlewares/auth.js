const jwt = require("jsonwebtoken")
require('dotenv').config()
const User = require('../models/user')

module.exports = async (req, res, next) => {
    const token = req.cookies.token || req.headers['x-access-token'] || req.query.token //|| req.boy.token
    if (!token) {
        // res.status(401).json({message: 'Token mavjud emas!'})
        res.status(401)
    }
    try {
        const decoded = await jwt.verify(token, process.env.SECRET)
        const user = await User.findById({ _id: decoded._id })
        req.user = user
        next()
    } catch (err) {
        // res.status(400).json({message: 'Token yaroqsiz!'})
        res.status(400)
    }
}