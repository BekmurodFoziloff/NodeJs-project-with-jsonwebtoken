const express = require('express')
const exphbs = require('express-handlebars')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const session = require('express-session')
const MongoStore = require('connect-mongodb-session')(session)
const cookieParser = require('cookie-parser')
const flash = require('connect-flash')
const csrf = require('csurf')
const path = require('path')
require('dotenv').config()
const app = express()
const homeRoutes = require('./routes/home')
const newsRoutes = require('./routes/news')
const authRoutes = require('./routes/auth')
const addRoutes = require('./routes/add')
const variablesMiddleware = require('./middlewares/variables')
const userMiddleware = require('./middlewares/user')
const errorHandler = require('./middlewares/error')

const hbs = exphbs.create({
    defaultLayout: 'main',
    extname: 'hbs',
    helpers: require('./utils/hbs-helpers')
})
const store = new MongoStore({
    collection: 'sessions',
    uri: process.env.MONGODB_URI
})

app.engine('hbs', hbs.engine)
app.set('view engine', 'hbs')
app.set('views', './views')

app.use(express.static(path.join(__dirname, 'public')))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(cookieParser())
app.use(flash())
app.use(csrf({ cookie: true }))
app.use(session({
    secret: 'jsonwebtoken',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 },
    store
}))

app.use(variablesMiddleware)
app.use(userMiddleware)

// app.use((req, res, next) => {
//     console.log(req.user)
//     console.log(req.session)
//     console.log(req.cookies)
//     next()
// })

app.use('/', homeRoutes)
app.use('/news', newsRoutes)
app.use('/auth', authRoutes)
app.use('/add', addRoutes)

app.use(errorHandler)

const PORT = process.env.PORT || 3000

async function start() {
    try {
        await mongoose.connect(process.env.MONGODB_URI)
        console.log('Connected to DB')
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`)
        })
    } catch (err) {
        console.log(err)
    }
}

start()


