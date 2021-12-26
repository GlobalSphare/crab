const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const path = require('path')
const config = require('./config/config.json')
const app = express()

const renderRouter = require('./routers/render')
const apiRouter = require('./routers/api')

app.use(session({
    resave: false,
    saveUninitialized: false,
    secret: 'c1',
    cookie: { maxAge: 3600 * 1000 * 24 }
}))

app.use(cookieParser())

// parser application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))
// parser application/json
app.use(bodyParser.json())

app.use(express.static(path.join(__dirname, '../public')))

app.set('views', path.resolve(__dirname, './views'))
app.set('view engine', 'ejs')

app.disable('x-powered-by')
app.use((req, res, next) => {
    res.set('x-powered-by', false)
    next()
})

app.use((req, res, next) => {
    if((req.path !== '/api/user/login') && !req.session['user']) {
        res.send({code: 40404 }) 
        return
    }
    
    next()
})

app.use('/api', apiRouter)

app.use('/', renderRouter)

app.listen(config.port, () => { console.log('serve is starting on port', config.port) })

