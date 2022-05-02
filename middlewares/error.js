module.exports = function(req, res, next) {
    res.status(404).render('error', {
        title: 'Sahifa topilmadi'
    })
}