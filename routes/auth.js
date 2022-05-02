const bcrypt = require('bcryptjs')
const { Router } = require('express')
const jwt = require('jsonwebtoken')
const { validationResult } = require('express-validator')
const { registerValidators } = require('../utils/validators')
const User = require('../models/user')
const router = Router()
require('dotenv').config()

router.get('/login', async (req, res) => {
    res.render('auth/login', {
        title: 'Kirish sahifasi',
        isLogin: true,
        loginError: req.flash('loginError'),
        registerError: req.flash('registerError')
    })
})

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body
        const candidate = await User.findOne({ email })
        if (candidate) {
            const areSame = await bcrypt.compare(password, candidate.password)
            if (areSame) {
                req.session.user = candidate
                req.session.isAuthenticated = true
                req.session.save((err) => {
                    if (err) {
                        throw err
                    }
                    const token = jwt.sign({ _id: candidate._id }, process.env.SECRET, { expiresIn: '1h' })
                    // res.header('x-access-token', token).send(true)
                    return res.cookie('token', token, {
                        maxAge: new Date(Date.now() + 60 * 60 * 1000),
                        secure: true,
                        httpOnly: true
                    }).redirect('/')
                })
            } else {
                req.flash('loginError', 'Parol noto\'g\'ri')
                res.redirect('/auth/login#login')
                // res.json('Parol noto\'g\'ri')
            }
        }
        else {
            req.flash('loginError', 'Email noto\'g\'ri')
            res.redirect('/auth/login#login')
            // res.json('Email noto\'g\'ri')
        }
    } catch (err) {
        console.log(err)
    }
})



router.get('/logout', async (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            throw err
        }
        res.redirect('/auth/login#login')
    })
})

router.post('/register', registerValidators, async (req, res) => {
    try {
        const { name, email, password, confirm } = req.body
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            req.flash('registerError', errors.array()[0].msg)
            return res.status(422).redirect('/auth/login#register')
        }
        const hashPassword = await bcrypt.hash(password, 10)
        const user = new User({
            name, email, password: hashPassword
        })
        user.save()
        res.redirect('/auth/login#login')
    } catch (err) {
        console.log(err)
    }
})

module.exports = router