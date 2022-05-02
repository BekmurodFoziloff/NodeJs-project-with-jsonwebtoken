const { Router } = require('express')
const router = Router()

router.get('/', (req, res) => {
    res.render('home', {
        title: 'Bosh sahifa',
        isHome: true
    })
})

module.exports = router