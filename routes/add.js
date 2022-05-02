const { Router } = require('express')
const Item = require('../models/item-add')
const { validationResult } = require('express-validator')
const { itemValidators } = require('../utils/validators')
const auth = require('../middlewares/auth')
const router = Router()

router.get('/', auth, (req, res) => {
    res.render('add', {
        title: 'Yangilik qo\'shish',
        isAdd: true
    })
})

router.post('/', auth, itemValidators, (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(422).render('add', {
            title: 'Yangilik qo\'shish',
            isAdd: true,
            error: errors.array()[0].msg,
            data: {
                title: req.body.img,
                price: req.body.head,
                img: req.body.text
            }
        })
    }
    const { img, head, text } = req.body
    const item = new Item({
        img, head, text, userId: req.user._id
    })
    try {
        item.save()
        res.redirect('/news')
    } catch (err) {
        console.log(err)
    }
})

module.exports = router