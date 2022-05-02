const { body } = require('express-validator')
const User = require('../models/user')

exports.registerValidators = [
    body('name')
        .isLength({ min: 3 })
        .withMessage('Ism kamida 3ta belgidan iborat bo\'lishi kerak')
        .isAlpha()
        .trim(),
    body('email')
        .isEmail()
        .withMessage('Emailni to\'g\'ri kiriting')
        .custom(async (value, { req }) => {
            try {
                const user = await User.findOne({ email: value })
                if (user) {
                    return Promise.reject('Bu emailga ega foydalanuvchi allaqachon mavjud')
                }
            } catch (err) {
                console.log(err)
            }
        })
        .normalizeEmail(),
    body('password')
        .isLength({ min: 6, max: 56 })
        .withMessage('Parol kamida 6 ta belgidan iborat bo\'lishi kerak')
        .isAlphanumeric()
        .trim(),
    body('confirm')
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Parollar bir xil bo\'lishi kerak')
            }
            return true
        })
        .trim()
]

exports.itemValidators = [
    body('img')
        .isURL()
        .withMessage('Rasm URLni to\'g\'ri kirirting'),
    body('head')
        .isLength({ min: 1 })
        .withMessage('Sarlavha bo\'sh bo\'lishi mumkin emas')
        .isString(),
    body('text')
        .isLength({ min: 1 })
        .withMessage('Matn bo\'sh bo\'lishi mumkin emas')
        .isString()
]
