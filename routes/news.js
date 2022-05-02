const { Router } = require('express')
const Item = require('../models/item-add')
const auth = require('../middlewares/auth')
const router = Router()

router.get('/', async (req, res) => {
    try {
        const items = await Item.find({}).lean().populate('userId')
        res.render('news', {
            title: 'Yangiliklar',
            isNews: true,
            items,
            userId: req.user ? req.user._id.toString() : null
        })
        // res.status(200).json(items)
    } catch (err) {
        console.log(err)
    }
})

router.get('/:id/edit', auth, async (req, res) => {
    try {
        if (!req.query.allow) {
            return res.redirect('/')
        }
        const item = await Item.findById(req.params.id).lean()
        res.render('item-edit', {
            title: 'Tahrirlash',
            item
        })
    } catch (err) {
        console.log(err)
    }
})

router.post('/edit', auth, async (req, res) => {
    try {
        const { id } = req.body
        delete req.body.id
        await Item.findByIdAndUpdate(id, req.body).lean()
        res.redirect('/news')
    } catch (err) {
        console.log(err)
    }
})

router.post('/remove', auth, async (req, res) => {
    try {
        await Item.deleteOne({ _id: req.body.id })
        res.redirect('/news')
    } catch (err) {
        console.log(err)
    }
})

router.get('/:id', async (req, res) => {
    try {
        const item = await Item.findById(req.params.id).lean()
        res.render('item-blank', {
            layout: 'empty',
            title: item.head,
            item
        })
    } catch (err) {
        console.log(err)
    }
})

module.exports = router